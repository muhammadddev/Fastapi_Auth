from __future__ import annotations

from typing import Callable, Dict, List, TYPE_CHECKING, Type

from src.authentication.domain import commands, events, model
from src.authentication.service_layer.exceptions import (
    DuplicateUsername,
    InvalidToken,
    InvalidUserId,
    InvalidUsername,
)

if TYPE_CHECKING:
    from src.authentication.service_layer import unit_of_work


def signup_user(cmd: commands.SignUp, uow: unit_of_work.AbstractUnitOfWork):
    with uow:
        creator_user = uow.users.get(username=cmd.creator_username)
        if creator_user is None:
            raise InvalidToken("InvalidToken")
        user = uow.users.get(username=cmd.username)
        if user:
            raise DuplicateUsername("User with this username already exists")
        user = model.User(
            cmd.username,
            cmd.email,
            cmd.password,
            cmd.role,
            cmd.is_active,
        )
        uow.users.add(user)
        uow.commit()


def add_plan(cmd: commands.AddPlan, uow: unit_of_work.AbstractUnitOfWork):
    with uow:
        admin_user = uow.users.get(username=cmd.admin_username)
        if admin_user is None:
            raise InvalidToken("InvalidToken")
        user = uow.users.get(username=cmd.username)
        if user is None:
            raise InvalidUsername("InvalidUsername")
        ip_list = [str(ip) for ip in cmd.ip_list]
        user.plan = model.Plan(ip_list, cmd.quota, cmd.api_call, cmd.expire_datetime)
        uow.commit()


def update_user(cmd: commands.UpdateUser, uow: unit_of_work.AbstractUnitOfWork):
    with uow:
        creator_user = uow.users.get(username=cmd.old_username)
        if creator_user is None:
            raise InvalidToken("InvalidToken")
        user = uow.users.get(username=cmd.new_username)
        if user:
            raise DuplicateUsername("User with this username already exists")
        new_user = model.User(
            cmd.new_username,
            cmd.email,
            cmd.password,
            creator_user.role_id,
            creator_user.is_active,
        )
        uow.users.update(cmd.old_username, new_user)
        uow.commit()


def delete_user(cmd: commands.DeleteUser, uow: unit_of_work.AbstractUnitOfWork):
    with uow:
        creator_user = uow.users.get(username=cmd.username)
        if creator_user is None:
            raise InvalidToken("InvalidToken")
        uow.users.delete(cmd.user_id)
        uow.commit()


def update_user_by_id(
    cmd: commands.UpdateUserById, uow: unit_of_work.AbstractUnitOfWork
):
    with uow:
        user = uow.users.get_by_id(cmd.user_id)
        if user is None:
            raise InvalidUserId("invalid user id")
        new_user = model.User(
            cmd.username, cmd.email, cmd.password, cmd.role_id, cmd.is_active
        )
        uow.users.update(user.username, new_user)
        uow.commit()


EVENT_HANDLERS: Dict[Type[events.Event], List[Callable]] = {}

COMMAND_HANDLERS: Dict[Type[commands.Command], Callable] = {
    commands.SignUp: signup_user,
    commands.AddPlan: add_plan,
    commands.UpdateUser: update_user,
    commands.DeleteUser: delete_user,
    commands.UpdateUserById: update_user_by_id,
}
