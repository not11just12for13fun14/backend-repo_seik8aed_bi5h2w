"""
Database Schemas for Chat App

Each Pydantic model represents a MongoDB collection. The collection name is the lowercase of the class name.
- User -> "user"
- Message -> "message"
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

class User(BaseModel):
    username: str = Field(..., min_length=2, max_length=32)
    email: EmailStr
    password: str = Field(..., min_length=8, description="Hashed password")
    status: str = Field("offline", description="online|offline")
    createdAt: Optional[datetime] = None

class Message(BaseModel):
    senderId: str = Field(..., description="sender user's id as string")
    receiverId: str = Field(..., description="receiver user's id as string")
    message: str = Field(..., min_length=1, max_length=5000)
    timestamp: Optional[datetime] = None
