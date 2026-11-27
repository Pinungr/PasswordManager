from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Username = Annotated[str, Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")]
Password = Annotated[str, Field(min_length=1, max_length=512, repr=False)]
Role = Literal["ADMIN", "TEAM_LEAD", "MEMBER"]
DisplayName = Annotated[str, Field(min_length=1, max_length=200, pattern=r"\S")]
Email = Annotated[str, Field(max_length=254, pattern=r"^[^\s@]+@[^\s@]+$")]


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class Login(Payload):
    username: Username
    password: Password

    @field_validator("username")
    @classmethod
    def normalize(cls, value: str) -> str:
        return value.lower()


UuidString = Annotated[str, Field(pattern=r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")]


class Assignments(Payload):
    team_ids: list[UuidString] = Field(default_factory=list)


class NewUser(Login):
    team_ids: list[UuidString] = Field(default_factory=list)
    full_name: DisplayName
    email: Email | None = None
    role: Role = "MEMBER"
    active: bool = True


class Signup(Login):
    full_name: DisplayName


class UpdateUser(Payload):
    full_name: DisplayName
    email: Email | None
    role: Role
    active: bool


class NewPassword(Payload):
    password: Password


class PrivatePasswordReset(Login):
    pass


class ChangePassword(NewPassword):
    current_password: Password


class Team(Payload):
    name: Annotated[str, Field(min_length=1, max_length=100, pattern=r"\S")]
    description: Annotated[str, Field(max_length=1000)] = ""
    lead_id: Annotated[str, Field(max_length=36)] | None = None
    active: bool = True
