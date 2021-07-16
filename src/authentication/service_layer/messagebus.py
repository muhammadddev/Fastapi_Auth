from __future__ import annotations

from typing import Callable, Dict, List, TYPE_CHECKING, Type, Union

from src.authentication.domain import commands, events

if TYPE_CHECKING:
    from src.authentication.service_layer import unit_of_work

Message = Union[commands.Command, events.Event]


class MessageBus:
    def __init__(
        self,
        uow: unit_of_work.AbstractUnitOfWork,
        event_handlers: Dict[Type[events.Event], List[Callable]],
        command_handlers: Dict[Type[commands.Command], Callable],
    ):
        self.uow = uow
        self.event_handlers = event_handlers
        self.command_handlers = command_handlers
        self._queue = []

    def handle(self, message: Message):
        self._queue.append(message)
        while self._queue:
            message = self._queue.pop(0)
            if isinstance(message, events.Event):
                self.handle_event(message)
            elif isinstance(message, commands.Command):
                self.handle_command(message)
            else:
                raise Exception(f"{message} was not an Event or Command")

    def handle_event(self, event: events.Event):
        for handler in self.event_handlers[type(event)]:
            try:
                handler(event)
                self._queue.extend(self.uow.collect_new_events())
            except Exception:
                continue

    def handle_command(self, command: commands.Command):
        try:
            handler = self.command_handlers[type(command)]
            handler(command)
            self._queue.extend(self.uow.collect_new_events())
        except Exception:
            raise
