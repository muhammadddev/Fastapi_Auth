import abc
from typing import Set

from src.authentication.domain import model


class AbstractRepository(abc.ABC):
    def __init__(self):
        self.seen: Set[model.User] = set()

    def add(self, user: model.User):
        self._add(user)
        self.seen.add(user)

    def get(self, username) -> model.User:
        user = self._get(username)
        if user:
            self.seen.add(user)
        return user

    def get_by_id(self, uuid) -> model.User:
        user = self._get_by_id(uuid)
        if user:
            self.seen.add(user)
        return user

    def update(self, username: str, user: model.User):
        self._update(username, user)
        self.seen.add(user)

    def delete(self, uuid):
        self._delete(uuid)

    @abc.abstractmethod
    def _add(self, user: model.User):
        raise NotImplementedError

    @abc.abstractmethod
    def _get(self, uuid) -> model.User:
        raise NotImplementedError

    @abc.abstractmethod
    def _get_by_id(self, uuid) -> model.User:
        raise NotImplementedError

    @abc.abstractmethod
    def _update(self, username: str, user: model.User):
        raise NotImplementedError

    @abc.abstractmethod
    def _delete(self, uuid):
        raise NotImplementedError


class SqlAlchemyRepository(AbstractRepository):
    def __init__(self, session):
        super().__init__()
        self.session = session

    def _add(self, user):
        self.session.add(user)

    def _get(self, username):
        return self.session.query(model.User).filter_by(username=username).first()

    def _get_by_id(self, uuid):
        return self.session.query(model.User).filter_by(uuid=str(uuid)).first()

    def _update(self, username, user):
        self.session.query(model.User).filter_by(username=username).update(
            {
                "username": user.username,
                "email": user.email,
                "password": user.password,
                "role_id": user.role_id,
                "is_active": user.is_active,
            }
        )

    def _delete(self, uuid):
        self.session.query(model.User).filter_by(uuid=str(uuid)).update(
            {"is_active": False}
        )
