from fastapi import FastAPI, Depends, HTTPException, status
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import InvalidTokenError
from pydantic import BaseModel
from pwdlib import PasswordHash
import jwt
from datetime import datetime, timedelta, timezone

SECRET_KEY = "b7a4ec743a42db57e0624e1f887d31e82cd13773caa21d041b72860f219a2cdf"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    username: str
    email: str | None = None
    password: str | None = None
    full_name: str | None = None
    is_active: bool | None = None

class UserInDB(User):
    hashed_password: str

passwordHash = PasswordHash.recommended()

Dummy_password = passwordHash.hash("dummypassword")


#credentials
fake_user_db = {
    "satorugojo": {
        "username": "satorugojo",
        "full_name": "Satoru Gojo",
        "email": "satoru@example.com",
        "hashed_password": passwordHash.hash("secret"),
        "is_active": True,
    },
    "janedoe": {
        "username": "janedoe",
        "full_name": "Jane Doe",
        "email": "janedoe@example.com",
        "hashed_password": passwordHash.hash("secret"),
        "is_active": False,
    }
}

def verify_password(plain_password, hashed_password):
    return passwordHash.verify(plain_password, hashed_password)

def get_password_hash(password):
    return passwordHash.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        verify_password(password, Dummy_password)
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
     credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
     try:
         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
         username = payload.get("sub")
         if username is None:
             raise credentials_exception
         token_data = TokenData(username=username)
     except InvalidTokenError:
         raise credentials_exception
     user = get_user(fake_user_db, username=token_data.username)
     if user is None:
         raise credentials_exception
     return user

def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = authenticate_user(fake_user_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")

@app.get('/users/me')
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]) -> User:
    return current_user


@app.get("/hello/name")
async def say_hello(current_user: Annotated[User, Depends(get_current_active_user)]) -> dict[str, str]:
    return {"message": f"Hello {current_user.full_name}"}
