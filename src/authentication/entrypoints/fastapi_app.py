import datetime
import ipaddress
from enum import IntEnum
from typing import List, Optional

import arrow
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, UUID4, ValidationError

from src.authentication import bootstrap, views
from src.authentication.config import Settings
from src.authentication.domain import commands
from src.authentication.service_layer.exceptions import (
    DuplicateUsername,
    InactiveUser,
    IncorrectPassword,
    InvalidToken,
    InvalidUserId,
    InvalidUsername,
)

app = FastAPI()
bus = bootstrap.bootstrap()


class Roles(IntEnum):
    admin = 1
    member = 2
    user = 3


class NewUser(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Roles
    is_active: bool

    class Config:
        use_enum_values = True


class User(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Roles
    is_active: bool


class ResponseUser(BaseModel):
    username: str
    email: EmailStr
    password: str
    role_id: int
    plan_id: int
    is_active: bool


class UpdateUser(BaseModel):
    username: str
    email: EmailStr
    password: str


class Plan(BaseModel):
    username: str
    ip_list: List[ipaddress.IPv4Address]
    quota: int
    api_call: Optional[int] = None
    expire_datetime: datetime.datetime


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str
    scopes: str = ""


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")


async def get_valid_user_token(
        security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)
) -> TokenData:
    if security_scopes.scopes:
        authenticate_value = f'Bearer scopes="{security_scopes.scope_str}"'
    else:
        authenticate_value = f"Bearer"
    try:
        secret_key, algorithm = Settings().get_jwt_secrets()
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": authenticate_value},
            )
        token_scopes = payload.get("scopes", "")
        token_data = TokenData(username=username, scopes=token_scopes)
        for scope in security_scopes.scopes:
            if scope not in token_data.scopes:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": authenticate_value},
                )
        return token_data

    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": authenticate_value},
        )


@app.post("/signup", status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def signup_new_user(
        new_user: NewUser,
        token_data: TokenData = Security(get_valid_user_token, scopes=["admin"]),
):
    try:
        cmd = commands.SignUp(
            token_data.username,
            new_user.username,
            new_user.email,
            pwd_context.hash(new_user.password),
            new_user.role,
            new_user.is_active,
        )
        bus.handle(cmd)
        return {}

    except (DuplicateUsername, InvalidToken) as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post(
    "/signin", response_model=Token, status_code=status.HTTP_200_OK, tags=["Auth"]
)
async def signin_user_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
):
    try:
        user = views.get_user_info(form_data.username, bus.uow)
        if not user:
            raise InvalidUsername("user not found")

        if not pwd_context.verify(form_data.password, user.password):
            raise IncorrectPassword("password is incorrect")

        if not user.is_active:
            raise InactiveUser("user is inactivated")

        if user.role == "admin":
            data = {
                "sub": user.username,
                "scopes": user.role,
                "exp": arrow.utcnow().shift(hours=1).datetime.timestamp(),
            }
        else:
            data = {
                "sub": user.username,
                "scopes": user.role,
                "exp": arrow.get(user.expire_datetime).datetime.timestamp(),
            }
        secret_key, algorithm = Settings().get_jwt_secrets()
        access_token = jwt.encode(data, secret_key, algorithm=algorithm)
        return {"access_token": access_token, "token_type": "Bearer"}

    except (InvalidUsername, IncorrectPassword, InactiveUser) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/plan/add", status_code=status.HTTP_201_CREATED, tags=["Plan"])
async def add_plan(
        plan: Plan, token_data: TokenData = Security(get_valid_user_token, scopes=["admin"])
):
    try:
        cmd = commands.AddPlan(
            token_data.username,
            plan.username,
            plan.ip_list,
            plan.quota,
            plan.api_call,
            plan.expire_datetime,
        )
        bus.handle(cmd)

    except (JWTError, InvalidToken, InvalidUsername):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/users/me", response_model=ResponseUser, tags=["User"])
async def get_current_user(
        token_data: TokenData = Security(get_valid_user_token, scopes=[])
):
    return views.get_user_by_username(token_data.username, bus.uow)


@app.put("/users/me", status_code=status.HTTP_200_OK, tags=["User"])
async def update_current_user(
        user: UpdateUser, token_data: TokenData = Security(get_valid_user_token, scopes=[])
):
    try:
        cmd = commands.UpdateUser(
            token_data.username,
            user.username,
            user.email,
            pwd_context.hash(user.password),
        )
        bus.handle(cmd)
    except (DuplicateUsername, InvalidToken) as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/users/{user_id:uuid}", response_model=ResponseUser, tags=["User"])
async def get_user_by_id(
        user_id: UUID4,
        token_data: TokenData = Security(get_valid_user_token, scopes=["admin"]),
):
    try:
        user = views.get_user_by_id(user_id, bus.uow)
        if user is None:
            raise InvalidUserId("InvalidUserId")
        return user
    except InvalidUserId as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.delete("/users/{user_id:uuid}", tags=["User"])
async def delete_user_by_id(
        user_id: UUID4,
        token_data: TokenData = Security(get_valid_user_token, scopes=["admin"]),
):
    try:
        cmd = commands.DeleteUser(token_data.username, user_id)
        bus.handle(cmd)

    except InvalidUserId as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.put("/users/{user_id:uuid}", tags=["User"])
async def update_user_by_id(
        user_id: UUID4,
        user: User,
        token_data: TokenData = Security(get_valid_user_token, scopes=["admin"]),
):
    try:
        cmd = commands.UpdateUserById(
            user_id,
            user.username,
            user.email,
            pwd_context.hash(user.password),
            user.role,
            user.is_active,
        )
        bus.handle(cmd)

    except InvalidUserId as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
