from fastapi import APIRouter, Body, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from hashlib import sha256
import uuid

router = APIRouter()

user_database = {}
token_db = {}

class LoginInput(BaseModel):
    email: str 
    password: str
    
class RegisterInput(BaseModel):
    username: str
    email: str
    address: Optional[str] = None
    password: str
    
class UserBO(BaseModel):
    username: str
    email: str
    address: Optional[str]
    hashed_password: str 
    
class IntrospectOutput(BaseModel):
    username: str
    email: str
    address: Optional[str]

def hash_password(random_string: str, password: str) -> str:
    return sha256((random_string + password).encode()).hexdigest()

@router.post("/register")
async def register(input: RegisterInput = Body()) -> dict:
    inner_object = UserBO(
        username = input.username,
        email = input.email,
        address = input.address,
        hashed_password = hash_password(input.email, input.password)
    )
    
    if inner_object.email in user_database:
        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )
    user_database[inner_object.email] = inner_object
    return {"status": "ok"}

@router.post("/login")
async def login(input: LoginInput = Body()) -> dict:
    if input.email not in user_database:
        raise HTTPException(
            status_code=404,
            detail="Email not registered"
        )
        
    if hash_password(input.email, input.password) != user_database[input.email].hashed_password:
        raise HTTPException(
            status_code=401,
            detail="Incorrect password"
        )
    
    random_id = str(uuid.uuid4())
    while random_id in token_db:
        random_id = str(uuid.uuid4())
        
    token_db[random_id] = input.email
    return {"auth": random_id}

@router.delete("/{id}")
async def delete_user(id: str) -> dict:
    if id in user_database:
        del user_database[id]
    return {"status": "ok"}

@router.get("/introspect")
async def introspect(auth: str = Header()) -> IntrospectOutput:
    if auth not in token_db:
        raise HTTPException(
            status_code=401,
            detail="Incorrect token"
        )
    
    current_email = token_db[auth]
    current_user = user_database[current_email]
    return IntrospectOutput(
        username=current_user.username,
        email=current_user.email,
        address=current_user.address
    )