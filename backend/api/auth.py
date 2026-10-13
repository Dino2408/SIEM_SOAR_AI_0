from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Any

router = APIRouter(prefix="/auth", tags=["auth"])

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
async def login(credentials: LoginRequest):
    """JWT login"""
    # Mock authentication
    if credentials.username == "admin" and credentials.password == "admin":
        return {"access_token": "mock_jwt_token_123", "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

@router.post("/refresh")
async def refresh_token():
    """Refresh token"""
    return {"access_token": "mock_jwt_token_456", "token_type": "bearer"}

@router.post("/logout")
async def logout():
    """Invalidate token"""
    return {"status": "success", "message": "Successfully logged out"}

@router.get("/me")
async def current_user():
    """Current user profile"""
    return {"username": "admin", "role": "admin", "email": "admin@siem.local"}

@router.post("/users")
async def create_user(user_data: Dict[str, Any]):
    """Create user (admin only)"""
    return {"id": "usr_new", "username": user_data.get("username")}

@router.get("/users")
async def list_users():
    """List users (admin only)"""
    return [{"id": "usr_1", "username": "admin"}]
