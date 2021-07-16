import environ


@environ.config(prefix="APP")
class AppConfig:
    @environ.config(prefix="POSTGRES")
    class PostgresqlConfig:
        uri = environ.secrets.INISecrets.from_path_in_env("APP_SECRET_INI").secret(
            name="db_uri", section="db_secrets"
        )

    secret_key = environ.secrets.INISecrets.from_path_in_env("APP_SECRET_INI").secret(
        name="secret_key", section="app_secrets"
    )
    jwt_algorithm = environ.secrets.INISecrets.from_path_in_env(
        "APP_SECRET_INI"
    ).secret(name="jwt_algorithm", section="app_secrets")

    postgres = environ.group(PostgresqlConfig)


class Settings:
    def __init__(self):
        self.cfg = AppConfig.from_environ()

    def get_postgres_uri(self) -> str:
        return str(self.cfg.postgres.uri)

    def get_jwt_secrets(self) -> [str, str]:
        return str(self.cfg.secret_key), str(self.cfg.jwt_algorithm)
