import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Literal, Self
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ACCOUNT_PASSWORD_MIN_LENGTH = 8
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)

    app_name: Literal["Pinaki SecureVault"] = "Pinaki SecureVault"
    environment: Literal["production", "development"] = "production"
    host_mode: Literal["local", "network"] = "local"
    hostname: str = "localhost"
    https_port: int = Field(18443, ge=1, le=65535)
    max_registered_users: int = Field(1000, ge=1)
    session_timeout_minutes: int = Field(480, ge=1)
    vault_auto_lock_minutes: int = Field(5, ge=1)
    secret_reveal_timeout_seconds: int = Field(30, ge=1)
    clipboard_clear_seconds: int = Field(30, ge=1)
    account_password_min_length: int = Field(
        ACCOUNT_PASSWORD_MIN_LENGTH, ge=ACCOUNT_PASSWORD_MIN_LENGTH, le=512
    )
    max_login_attempts: int = Field(5, ge=1)
    login_lockout_minutes: int = Field(15, ge=1)
    password_history_limit: int = Field(10, ge=1)
    recycle_bin_retention_days: int = Field(30, ge=1)
    backup_retention_days: int = Field(7, ge=1)
    backup_schedule: str = Field("02:00", pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
    max_fields_per_credential: int = Field(100, ge=1)
    max_field_value_bytes: int = Field(65536, ge=1)
    timezone: str = "Asia/Kolkata"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    default_theme: Literal["light", "dark", "system"] = "light"

    @field_validator("hostname")
    @classmethod
    def valid_hostname(cls, value: str) -> str:
        if "%" in value:
            raise ValueError("configure a hostname or unscoped IP address")
        value = value.lower()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            if len(value) > 253 or not all(HOST_LABEL.fullmatch(n) for n in value.split(".")):
                raise ValueError("configure a hostname or IP address") from None
            return value
        if address.is_unspecified or address.is_multicast:
            raise ValueError("configure a reachable hostname or IP address")
        return str(address)

    @field_validator("timezone")
    @classmethod
    def installed_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (KeyError, ValueError):
            raise ValueError("configure an IANA time zone") from None
        return value

    @model_validator(mode="after")
    def hosting_mode(self) -> Self:
        loopback = self.hostname in {"localhost", "127.0.0.1", "::1"}
        if (self.host_mode == "local") != loopback:
            raise ValueError("hostname must match the selected host mode")
        return self

    @property
    def authority(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return host if self.https_port == 443 else f"{host}:{self.https_port}"

    @property
    def origin(self) -> str:
        return f"https://{self.authority}"


def load_settings() -> Settings:
    path = os.environ.get("SECUREVAULT_CONFIG_FILE")
    values = {}
    if path:
        with Path(path).open(encoding="utf-8-sig") as stream:
            values = json.load(stream)
        if not isinstance(values, dict):
            raise ValueError("Configuration must be a JSON object")
    aliases = {"https_port": "SECUREVAULT_PUBLISH_PORT"}
    for field, definition in Settings.model_fields.items():
        variable = aliases.get(field, f"SECUREVAULT_{field.upper()}")
        value = os.environ.get(variable)
        if value is not None:
            values[field] = int(value) if definition.annotation is int else value
    settings = Settings.model_validate(values)
    publish_ip = os.environ.get("SECUREVAULT_PUBLISH_IP")
    if (
        publish_ip is not None
        and settings.host_mode == "local"
        and not ipaddress.ip_address(publish_ip).is_loopback
    ):
        raise ValueError("local mode requires a loopback host port binding")
    return settings


def read_hex_secret(name: str) -> str:
    direct = os.environ.get(name)
    file = os.environ.get(f"{name}_FILE")
    if direct is not None and file is not None:
        raise ValueError(f"Configure only one source for {name}")
    value = direct if file is None else Path(file).read_text(encoding="ascii").rstrip("\r\n")
    if value is None or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise ValueError(f"{name} requires 32 random bytes as 64 hexadecimal characters")
    if len(set(value.lower())) < 8:
        raise ValueError(f"{name} requires cryptographically random bytes")
    return value.lower()
