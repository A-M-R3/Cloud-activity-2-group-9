from fastapi import FastAPI
from app.authentication.router import router as auth_router
from app.files.router import router as files_router


app = FastAPI()

app.include_router(auth_router, prefix="/authentication", tags=["Authentication"])
app.include_router(files_router, prefix="/files", tags=["Files"])