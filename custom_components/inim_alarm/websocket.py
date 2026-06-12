"""WebSocket client for INIM Cloud real-time updates."""

import asyncio
import json
import logging
import random
import time
from typing import Any, Callable
from urllib.parse import quote

import aiohttp

from .api import InimApi

_LOGGER = logging.getLogger(__name__)

WS_URL = "wss://ws.inimcloud.com/events"
PING_INTERVAL = 115  # Server timeout is ~120s, ping a bit earlier
HEARTBEAT_PAYLOAD = "@"
WATCHDOG_INTERVAL = 15
HEARTBEAT_TIMEOUT = (PING_INTERVAL * 2) + 30
RECONNECT_BASE_DELAY = 3.0
RECONNECT_MAX_DELAY = 60.0
RECONNECT_JITTER = 0.2
LOG_REDACTED = "**REDACTED**"
WS_LOG_SENSITIVE_KEYS = {
    "deviceeventid",
    "deviceid",
    "id",
    "name",
    "ulid",
}


def _redact_ws_message_for_log(text: str) -> str:
    """Redact sensitive values while preserving WebSocket debug details."""
    if text == HEARTBEAT_PAYLOAD:
        return text

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return "**UNPARSEABLE MESSAGE REDACTED**"

    return json.dumps(
        _redact_ws_value_for_log(payload),
        separators=(",", ":"),
    )


def _redact_ws_value_for_log(value: Any) -> Any:
    """Return a redacted copy of a nested WebSocket value."""
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = "".join(
                character
                for character in str(key).casefold()
                if character.isalnum()
            )
            if normalized_key in WS_LOG_SENSITIVE_KEYS:
                redacted[key] = LOG_REDACTED
            elif normalized_key == "data" and isinstance(item, str):
                redacted[key] = _redact_nested_json_for_log(item)
            else:
                redacted[key] = _redact_ws_value_for_log(item)
        return redacted

    if isinstance(value, list):
        return [_redact_ws_value_for_log(item) for item in value]

    return value


def _redact_nested_json_for_log(value: str) -> str:
    """Redact a JSON string nested inside a WebSocket event."""
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return LOG_REDACTED

    return json.dumps(
        _redact_ws_value_for_log(parsed),
        separators=(",", ":"),
    )


class InimWebSocketClient:
    """Client for INIM Cloud WebSocket events."""

    def __init__(
        self,
        api: InimApi,
        on_event: Callable[[dict[str, Any]], None],
    ) -> None:
        """Initialize the WebSocket client."""
        self._api = api
        self._on_event = on_event
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._run_task: asyncio.Task | None = None
        self._ping_task: asyncio.Task | None = None
        self._watchdog_task: asyncio.Task | None = None
        self._is_running = False
        self._last_rx_monotonic = time.monotonic()
        self._next_reconnect_delay = RECONNECT_BASE_DELAY

    async def start(self) -> None:
        """Start the WebSocket client."""
        if self._is_running:
            return

        self._is_running = True
        self._last_rx_monotonic = time.monotonic()
        self._next_reconnect_delay = RECONNECT_BASE_DELAY
        self._run_task = asyncio.create_task(self._listen_loop())
        self._ping_task = asyncio.create_task(self._ping_loop())
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())

    async def stop(self) -> None:
        """Stop the WebSocket client."""
        self._is_running = False

        if self._ws and not self._ws.closed:
            await self._ws.close()

        await self._cancel_task(self._ping_task)
        self._ping_task = None

        await self._cancel_task(self._watchdog_task)
        self._watchdog_task = None

        await self._cancel_task(self._run_task)
        self._run_task = None

    async def _cancel_task(self, task: asyncio.Task | None) -> None:
        """Cancel and await a task, ignoring cancellation errors."""
        if not task:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _get_ws_url(self) -> str:
        """Construct the WebSocket connection URL with auth."""
        if not self._api.is_authenticated:
            await self._api.authenticate()

        req_data = {
            "Node": "inimhome",
            "Name": "it.inim.inimutenti",
            "ClientIP": "",
            "Method": "WebSocketStart",
            "Token": self._api.token,
            "ClientId": self._api.client_id,
            "Context": None,
            "Params": {"Brand": 0},
        }

        req_json = json.dumps(req_data, separators=(",", ":"))
        return f"{WS_URL}?req={quote(req_json)}"

    async def _listen_loop(self) -> None:
        """Main listening loop with auto-reconnect."""
        while self._is_running:
            try:
                session = await self._api.get_session()
                url = await self._get_ws_url()

                _LOGGER.debug("Connecting to INIM WebSocket")
                async with session.ws_connect(url, heartbeat=None) as ws:
                    self._ws = ws
                    self._mark_rx()
                    self._reset_reconnect_backoff()
                    _LOGGER.info("Connected to INIM WebSocket")

                    async for msg in ws:
                        if not self._is_running:
                            break

                        self._mark_rx()

                        if msg.type == aiohttp.WSMsgType.TEXT:
                            self._handle_message(msg.data)
                        elif msg.type in (
                            aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.ERROR,
                        ):
                            _LOGGER.warning("WebSocket closed/error: %s", msg)
                            break

            except asyncio.CancelledError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as err:
                _LOGGER.warning(
                    "WebSocket connection error: %s",
                    err,
                )
            except Exception:
                _LOGGER.exception("Unexpected error in WebSocket loop")
            finally:
                self._ws = None

            if self._is_running:
                delay = self._consume_reconnect_delay()
                _LOGGER.debug("Reconnecting WebSocket in %.1fs", delay)
                await asyncio.sleep(delay)

    def _handle_message(self, text: str) -> None:
        """Parse and dispatch a WebSocket message."""
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "WS message: %r",
                _redact_ws_message_for_log(text),
            )

        if text == HEARTBEAT_PAYLOAD:
            _LOGGER.debug("Received INIM WS heartbeat")
            return

        try:
            data = json.loads(text)
        except json.JSONDecodeError as err:
            _LOGGER.error("Failed to parse WS message: %s", err)
            return

        if not isinstance(data, dict):
            _LOGGER.debug("Ignoring WS payload with unexpected type: %s", type(data).__name__)
            return

        msg_type = data.get("Type")

        if msg_type == "EVENT":
            event_data = data.get("Data", {})
            if not isinstance(event_data, dict):
                _LOGGER.debug("Ignoring EVENT message with invalid Data field")
                return

            inner_data_raw = event_data.get("Data")
            inner_data: dict[str, Any] | None = None
            if isinstance(inner_data_raw, str) and inner_data_raw:
                try:
                    parsed_data = json.loads(inner_data_raw)
                    if isinstance(parsed_data, dict):
                        inner_data = parsed_data
                    else:
                        _LOGGER.debug(
                            "Ignoring inner WS payload with unexpected type: %s",
                            type(parsed_data).__name__,
                        )
                        return
                except json.JSONDecodeError as err:
                    _LOGGER.error("Failed to parse inner WS payload: %s", err)
                    return
            elif isinstance(inner_data_raw, dict):
                inner_data = inner_data_raw

            if inner_data is not None:
                self._on_event(inner_data)
        elif msg_type == "PONG":
            _LOGGER.debug("Received PONG from INIM WS")
        else:
            _LOGGER.debug("Unknown WS message type: %s", msg_type)

    async def _ping_loop(self) -> None:
        """Send keep-alive pings at regular intervals."""
        while self._is_running:
            await asyncio.sleep(PING_INTERVAL)
            if not self._is_running:
                break

            if self._ws and not self._ws.closed:
                try:
                    await self._ws.send_str(HEARTBEAT_PAYLOAD)
                    _LOGGER.debug("Sent INIM WS ping")
                except asyncio.CancelledError:
                    raise
                except Exception as err:
                    _LOGGER.warning("Failed to send WS ping: %s", err)
                    if not self._ws.closed:
                        await self._ws.close()

    async def _watchdog_loop(self) -> None:
        """Watch for stale WebSocket connections and force reconnect."""
        while self._is_running:
            await asyncio.sleep(WATCHDOG_INTERVAL)
            if not self._is_running:
                break

            ws = self._ws
            if not ws or ws.closed:
                continue

            age = time.monotonic() - self._last_rx_monotonic
            if age > HEARTBEAT_TIMEOUT:
                _LOGGER.warning(
                    "WS heartbeat timeout (%.1fs without data), forcing reconnect",
                    age,
                )
                try:
                    await ws.close()
                except Exception as err:
                    _LOGGER.debug("Failed to close stale WS: %s", err)

    def _mark_rx(self) -> None:
        """Track last incoming WebSocket traffic time."""
        self._last_rx_monotonic = time.monotonic()

    def _reset_reconnect_backoff(self) -> None:
        """Reset reconnect delay after successful connection."""
        self._next_reconnect_delay = RECONNECT_BASE_DELAY

    def _consume_reconnect_delay(self) -> float:
        """Get reconnect delay with jitter and prepare next backoff value."""
        jitter = 1 + random.uniform(-RECONNECT_JITTER, RECONNECT_JITTER)
        delay = max(1.0, self._next_reconnect_delay * jitter)
        self._next_reconnect_delay = min(
            self._next_reconnect_delay * 2,
            RECONNECT_MAX_DELAY,
        )
        return delay
