from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import hashlib
import uuid

router = APIRouter()

# Internal Business Object (UserBO)
class UserBO:
    def __init__(self, external_id: int, email: str, password_hash: str):
        self.external_id = external_id
        self.email = email
        self.password_hash = password_hash

# Independent Pydantic Models for each endpoint
class RegisterInput(BaseModel):
    email: str
    password: str

class LoginInput(BaseModel):
    email: str
    password: str

# Local storage with global dictionaries
users_db = {}  # email -> UserBO
active_sessions = {}  # token -> user_id (int)

# Salted Hashing using hashlib.sha256
def get_password_hash(password: str, salt: str):
    password_with_salt = password + salt
    return hashlib.sha256(password_with_salt.encode()).hexdigest()

@router.post('/register') # Defaults to 200 status code
def register(data: RegisterInput):
    if data.email in users_db:
        # Code 409
        raise HTTPException(status_code=409, detail="User already exists")
    
    # Requirement: Unique integer external identifier
    user_id = len(users_db) + 1
    
    hashed_pwd = get_password_hash(data.password, data.email)
    new_user = UserBO(external_id=user_id, email=data.email, password_hash=hashed_pwd)
    
    users_db[data.email] = new_user
    return {"status": "success", "user_id": user_id}

@router.post('/login')
def login(data: LoginInput):
    user_bo = users_db.get(data.email)
    
    # Requirement: Specific error codes (404 and 401)
    if not user_bo:
        raise HTTPException(status_code=404, detail="Email not registered")
    
    input_hash = get_password_hash(data.password, data.email)
    if user_bo.password_hash != input_hash:
        raise HTTPException(status_code=401, detail="Incorrect password")
    
    # Requirement: Unique token string using the uuid module
    token = str(uuid.uuid4())
    active_sessions[token] = user_bo.external_id
    
    return {"token": token}

@router.post('/logout')
def logout(Auth: str = Header(None)): # Header requirement: "Auth"
    if Auth in active_sessions:
        active_sessions.pop(Auth)
    return {"status": "success"}

@router.get('/introspect')
def introspect(Auth: str = Header(None)):
    user_id = active_sessions.get(Auth)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return {"user_id": user_id}