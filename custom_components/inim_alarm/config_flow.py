"""Config flow for INIM Alarm integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import InimApi, InimApiError, InimAuthError
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_ENABLE_SIA,
    CONF_FULL_REFRESH_INTERVAL,
    CONF_SCAN_INTERVAL,
    CONF_SIA_ACCOUNT,
    CONF_SIA_PORT,
    CONF_USER_CODE,
    DEFAULT_FULL_REFRESH_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SIA_PORT,
    DOMAIN,
    MAX_FULL_REFRESH_INTERVAL_SECONDS,
    MAX_SCAN_INTERVAL_SECONDS,
    MIN_FULL_REFRESH_INTERVAL_SECONDS,
    MIN_SCAN_INTERVAL_SECONDS,
)

_LOGGER = logging.getLogger(__name__)

# Setup schema includes user_code for API operations
STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_USER_CODE): str,  # Required for bypass/area control
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect."""
    session = async_get_clientsession(hass)
    api = InimApi(
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        session=session,
    )

    try:
        await api.authenticate()
        devices = await api.get_devices()

        if not devices:
            raise InimApiError("No devices found")

        # Get the first device info for the title
        first_device = devices[0]
        title = first_device.get("Name", "INIM Alarm")

        return {
            "title": title,
            "device_count": len(devices),
        }

    except InimAuthError as err:
        raise InvalidAuth from err
    except InimApiError as err:
        raise CannotConnect from err


class InimAlarmConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for INIM Alarm."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return InimAlarmOptionsFlow()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                # Check if already configured
                await self.async_set_unique_id(user_input[CONF_USERNAME].lower())
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=info["title"],
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Handle reauthorization."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauthorization confirmation."""
        errors: dict[str, str] = {}

        if user_input is not None:
            reauth_entry = self._get_reauth_entry()

            try:
                await validate_input(
                    self.hass,
                    {
                        CONF_USERNAME: reauth_entry.data[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                    },
                )
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_update_reload_and_abort(
                    reauth_entry,
                    data={
                        **reauth_entry.data,
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                    },
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            errors=errors,
        )


class CannotConnect(Exception):
    """Error to indicate we cannot connect."""


class InvalidAuth(Exception):
    """Error to indicate there is invalid auth."""


class InimAlarmOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for INIM Alarm."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        errors: dict[str, str] = {}

        if user_input is not None:
            if (
                user_input[CONF_FULL_REFRESH_INTERVAL]
                < user_input[CONF_SCAN_INTERVAL]
            ):
                errors[CONF_FULL_REFRESH_INTERVAL] = "full_refresh_too_short"
            else:
                return self.async_create_entry(title="", data=user_input)

        # Get current values
        current_sia = self.config_entry.options.get(
            CONF_ENABLE_SIA,
            self.config_entry.data.get(CONF_ENABLE_SIA, False),
        )
        current_sia_port = self.config_entry.options.get(
            CONF_SIA_PORT,
            self.config_entry.data.get(CONF_SIA_PORT, DEFAULT_SIA_PORT),
        )
        current_sia_account = self.config_entry.options.get(
            CONF_SIA_ACCOUNT,
            self.config_entry.data.get(CONF_SIA_ACCOUNT, ""),
        )
        current_scan_interval = self.config_entry.options.get(
            CONF_SCAN_INTERVAL,
            int(DEFAULT_SCAN_INTERVAL.total_seconds()),
        )
        current_full_refresh_interval = self.config_entry.options.get(
            CONF_FULL_REFRESH_INTERVAL,
            int(DEFAULT_FULL_REFRESH_INTERVAL.total_seconds()),
        )
        current_scan_interval = min(
            MAX_SCAN_INTERVAL_SECONDS,
            max(MIN_SCAN_INTERVAL_SECONDS, int(current_scan_interval)),
        )
        current_full_refresh_interval = min(
            MAX_FULL_REFRESH_INTERVAL_SECONDS,
            max(
                MIN_FULL_REFRESH_INTERVAL_SECONDS,
                int(current_full_refresh_interval),
            ),
        )

        if (
            user_input is None
            and current_sia
            and current_scan_interval <= DEFAULT_SCAN_INTERVAL.total_seconds()
        ):
            current_scan_interval = int(
                DEFAULT_FULL_REFRESH_INTERVAL.total_seconds()
            )

        if user_input is None and current_full_refresh_interval < current_scan_interval:
            current_full_refresh_interval = current_scan_interval

        if user_input is not None:
            current_scan_interval = user_input[CONF_SCAN_INTERVAL]
            current_full_refresh_interval = user_input[CONF_FULL_REFRESH_INTERVAL]
            current_sia = user_input.get(CONF_ENABLE_SIA, False)
            current_sia_port = user_input.get(CONF_SIA_PORT, DEFAULT_SIA_PORT)
            current_sia_account = user_input.get(CONF_SIA_ACCOUNT, "")

        options_schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=current_scan_interval,
                ): vol.All(
                    vol.Coerce(int),
                    vol.Range(
                        min=MIN_SCAN_INTERVAL_SECONDS,
                        max=MAX_SCAN_INTERVAL_SECONDS,
                    ),
                ),
                vol.Required(
                    CONF_FULL_REFRESH_INTERVAL,
                    default=current_full_refresh_interval,
                ): vol.All(
                    vol.Coerce(int),
                    vol.Range(
                        min=MIN_FULL_REFRESH_INTERVAL_SECONDS,
                        max=MAX_FULL_REFRESH_INTERVAL_SECONDS,
                    ),
                ),
                vol.Optional(
                    CONF_ENABLE_SIA,
                    default=current_sia,
                ): bool,
                vol.Optional(
                    CONF_SIA_PORT,
                    default=current_sia_port,
                ): cv.port,
                vol.Optional(
                    CONF_SIA_ACCOUNT,
                    default=current_sia_account,
                ): str,
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=options_schema,
            errors=errors,
        )
