from uuid import UUID

from src.authentication.service_layer import unit_of_work


def get_user_info(username: str, uow: unit_of_work.SqlAlchemyUnitOfWork):
    with uow:
        result = uow.session.execute(
            """ SELECT *  
                FROM users u
                    LEFT JOIN plans p ON u.plan_id = p.id 
                    LEFT JOIN roles r on u.role_id = r.id 
                WHERE u.username = :username """,
            dict(username=username),
        ).fetchone()
    return result


def get_user_by_username(username: str, uow: unit_of_work.SqlAlchemyUnitOfWork):
    with uow:
        result = uow.session.execute(
            """ SELECT * 
                FROM users u 
                WHERE u.username = :username """,
            dict(username=username),
        ).fetchone()
    return result


def get_user_by_id(user_id: UUID, uow: unit_of_work.SqlAlchemyUnitOfWork):
    with uow:
        result = uow.session.execute(
            """ SELECT *
                FROM users u 
                WHERE u.uuid = :user_id """,
            dict(user_id=str(user_id)),
        ).fetchone()
    return result
