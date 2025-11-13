import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Message as MessageSchema

# JWT Config
SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Auth Helpers ----------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(lambda authorization: authorization), authorization: str = Depends(lambda: None)):
    # Extract token from Authorization header "Bearer <token>"
    from fastapi import Request
    # Custom dependency to access headers
    def _extract_token(request: Request) -> str:
        auth = request.headers.get("Authorization")
        if not auth:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        parts = auth.split()
        if parts[0].lower() != "bearer" or len(parts) != 2:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth header")
        return parts[1]

    try:
        from fastapi import Request
        request = Request(scope={"type": "http"})  # Fallback, but we'll re-fetch from context in route
    except Exception:
        request = None

    # This is a workaround since FastAPI dependencies in this environment are simplified.
    # We'll re-implement as a direct function inside routes using a helper below.
    return None

# Helper to read current user from request
from fastapi import Request

def current_user_from_request(request: Request):
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    parts = auth.split()
    if parts[0].lower() != "bearer" or len(parts) != 2:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth header")
    token = parts[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


@app.get("/")
def read_root():
    return {"message": "Chat API running"}

# ---------- Auth Endpoints ----------
@app.post("/api/auth/register", response_model=Token)
def register(payload: RegisterRequest):
    # Check if user exists
    existing = db["user"].find_one({"$or": [{"email": payload.email}, {"username": payload.username}]})
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed = get_password_hash(payload.password)
    user_doc = {
        "username": payload.username,
        "email": payload.email,
        "password": hashed,
        "status": "offline",
        "createdAt": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    user_id = str(res.inserted_id)

    access_token = create_access_token({"sub": user_id})
    return Token(access_token=access_token)


@app.post("/api/auth/login", response_model=Token)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("password", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # set online
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"status": "online"}})

    access_token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=access_token)


# ---------- Users ----------
class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr
    status: str


@app.get("/api/users", response_model=List[UserOut])
def list_users():
    users = []
    for u in db["user"].find({}, {"password": 0}):
        users.append(UserOut(id=str(u["_id"]), username=u.get("username", ""), email=u.get("email", ""), status=u.get("status", "offline")))
    return users


# ---------- Messages ----------
class SendMessageRequest(BaseModel):
    receiverId: str
    message: str

class MessageOut(BaseModel):
    id: str
    senderId: str
    receiverId: str
    message: str
    timestamp: datetime


@app.get("/api/messages/{user_id}", response_model=List[MessageOut])
def get_messages(user_id: str, request: Request):
    # current user
    me = current_user_from_request(request)
    # find messages where (sender=me and receiver=user_id) or (sender=user_id and receiver=me)
    msgs = db["message"].find({
        "$or": [
            {"senderId": me, "receiverId": user_id},
            {"senderId": user_id, "receiverId": me}
        ]
    }).sort("timestamp", 1)

    out = [
        MessageOut(
            id=str(m.get("_id")),
            senderId=m.get("senderId"),
            receiverId=m.get("receiverId"),
            message=m.get("message"),
            timestamp=m.get("timestamp", datetime.now(timezone.utc))
        ) for m in msgs
    ]
    return out


@app.post("/api/messages", response_model=MessageOut)
def send_message(payload: SendMessageRequest, request: Request):
    me = current_user_from_request(request)
    doc = {
        "senderId": me,
        "receiverId": payload.receiverId,
        "message": payload.message,
        "timestamp": datetime.now(timezone.utc)
    }
    res = db["message"].insert_one(doc)
    doc["_id"] = res.inserted_id
    # For MVP without WebSocket, the client can poll; later we can add Socket.IO-equivalent via websockets
    return MessageOut(
        id=str(doc["_id"]),
        senderId=doc["senderId"],
        receiverId=doc["receiverId"],
        message=doc["message"],
        timestamp=doc["timestamp"],
    )


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
