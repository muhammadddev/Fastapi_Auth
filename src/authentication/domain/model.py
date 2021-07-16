from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


class User:
    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        role: int,
        is_active: bool,
        plan: Optional[Plan] = None,
    ):
        self.username = username
        self.email = email
        self.password = password
        self.role_id = role
        self.is_active = is_active
        self.plan_id = plan
        self.events = []


@dataclass(unsafe_hash=True)
class Role:
    id: int
    role: str


@dataclass(unsafe_hash=True)
class Plan:
    ip: List[str]
    quota: int
    api_call: Optional[int]
    expire_datetime: datetime
