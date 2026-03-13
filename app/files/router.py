from fastapi import APIRouter, HTTPException, Header, Body
from pydantic import BaseModel
from typing import Optional
import uuid

router = APIRouter()

files_db = {}

class FileInput(BaseModel):
    filename: str
    description: Optional[str] = None

class FileBO(BaseModel):
    file_id: str
    owner_email: str
    filename: str
    description: Optional[str] = None

@router.post("")
async def files_post(input: FileInput = Body(), auth: str = Header()) -> dict:
    from app.authentication.router import token_db
    if auth not in token_db:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    owner_email = token_db[auth]
    file_id = str(uuid.uuid4())
    
    new_file = FileBO(
        file_id=file_id,
        owner_email=owner_email,
        filename=input.filename,
        description=input.description
    )
    files_db[file_id] = new_file
    return {"status": "ok", "file_id": file_id}

@router.get("")
async def files_get(auth: str = Header()) -> dict:
    from app.authentication.router import token_db
    if auth not in token_db:
        raise HTTPException(status_code=401, detail="Invalid token")
        
    owner_email = token_db[auth]
    user_files = [file for file in files_db.values() if file.owner_email == owner_email]
    return {"files": user_files}

@router.get("/{id}")
async def files_id_get(id: str): return {"status": "pending phase 3"}

@router.post("/{id}")
async def files_id_post(id: str): return {"status": "pending phase 3"}

@router.delete("/{id}")
async def files_id_delete(id: str): return {"status": "pending phase 3"}

@router.post("/merge")
async def files_merge_post(): return {"status": "pending phase 3"}