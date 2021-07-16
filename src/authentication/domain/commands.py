import datetime
from dataclasses import dataclass
from typing import List, Optional

from pydantic import UUID4


class Command:
    pass


@dataclass
class SignUp(Command):
    creator_username: str
    username: str
    email: str
    password: str
    role: int
    is_active: bool


@dataclass
class AddPlan(Command):
    admin_username: str
    username: str
    ip_list: List
    quota: int
    api_call: Optional[int]
    expire_datetime: datetime.datetime


@dataclass
class UpdateUser(Command):
    old_username: str
    new_username: str
    email: str
    password: str


@dataclass
class SearchSingleAddress(Command):
    username: str
    scopes: str
    address: str
    province_code: int
    region_code: int


@dataclass
class DeleteUser(Command):
    username: str
    user_id: UUID4


@dataclass
class UpdateUserById(Command):
    user_id: UUID4
    username: str
    email: str
    password: str
    role_id: int
    is_active: bool
