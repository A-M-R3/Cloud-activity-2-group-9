from fastapi import APIRouter, HTTPException
import secrets

router = APIRouter()

# Global dictionaries for local storage
users_db = {}
active_sessions = {}

@router.post('/register')
def register(email: str, password: str):
    # Check if the user already exists to avoid duplication
    if email in users_db:
        raise HTTPException(status_code=409, detail='User already exists')
    
    # Unique integer external identifier for the user
    user_id = len(users_db) + 1
    
    # Store the user information in our local dictionary
    users_db[email] = {
        'id': user_id,
        'email': email,
        'password': password
    }
    
    # Return a 200 success response
    return {'status': 'success', 'user_id': user_id}

@router.post('/login')
def login(email: str, password: str):
    # Retrieve the user from our local database
    user = users_db.get(email)
    
    # Check if the user exists and if the password matches
    if not user or user['password'] != password:
        # The professor noted that 403 is used when credentials are not correct
        raise HTTPException(status_code=403, detail='Invalid credentials')
    
    # Generate a secure 32 character hexadecimal token
    token = secrets.token_hex(16)
    
    # Store the session, linking the token to the user's unique ID
    active_sessions[token] = user['id']
    
    # Return the token to the user
    return {'token': token}