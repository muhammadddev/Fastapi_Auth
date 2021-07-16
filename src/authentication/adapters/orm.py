import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    event,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import registry, relationship

from src.authentication.domain import model

mapper_registry = registry()

users = Table(
    "users",
    mapper_registry.metadata,
    Column(
        "uuid", UUID(as_uuid=True), primary_key=True, unique=True, default=uuid.uuid4()
    ),
    Column("username", String(255), index=True),
    Column("email", String(255)),
    Column("password", String(255)),
    Column("role_id", ForeignKey("roles.id")),
    Column("plan_id", ForeignKey("plans.id"), nullable=True),
    Column("is_active", Boolean),
)

plans = Table(
    "plans",
    mapper_registry.metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ip", ARRAY(String)),
    Column("quota", Integer),
    Column("api_call", Integer, nullable=True),
    Column("expire_datetime", DateTime),
)

roles = Table(
    "roles",
    mapper_registry.metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("role", String(63)),
)


def start_mappers():
    mapper_registry.map_imperatively(model.Role, roles)
    plan_mapper = mapper_registry.map_imperatively(model.Plan, plans)
    mapper_registry.map_imperatively(
        model.User, users, properties={"plan": relationship(plan_mapper)}
    )


@event.listens_for(model.User, "load")
def receive_load(user, _):
    user.events = []
