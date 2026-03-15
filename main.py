from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String, Text, text as sql_text
from sqlalchemy.orm import sessionmaker, declarative_base
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from typing import Dict, Optional
from datetime import datetime, timedelta
import secrets
import os
import smtplib
import ssl
from urllib import request as urlrequest, parse as urlparse
import base64
import json

# ======================
# CONFIG
# ======================
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

app = FastAPI()

frontend_origins = [
    origin.strip() for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:8788"
    ).split(",") if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_origin_regex=r"https://.*\.pages\.dev",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================
# DATABASE
# ======================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./users.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    phone = Column(String, default="")
    profile_image = Column(Text, default="")
    password = Column(String)


class PublicKey(Base):
    __tablename__ = "public_keys"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    public_key_jwk = Column(Text)


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    sender = Column(String, index=True)
    recipient = Column(String, index=True)
    ciphertext = Column(Text)
    iv = Column(Text, default="")


Base.metadata.create_all(bind=engine)


def ensure_schema():
    # Keep existing local SQLite DBs compatible with the new profile image field.
    if not DATABASE_URL.startswith("sqlite"):
        return

    with engine.begin() as conn:
        rows = conn.execute(sql_text("PRAGMA table_info(users)")).fetchall()
        columns = {row[1] for row in rows}
        if "profile_image" not in columns:
            conn.execute(sql_text("ALTER TABLE users ADD COLUMN profile_image TEXT DEFAULT ''"))


ensure_schema()

# ======================
# SECURITY
# ======================
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)


def create_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def get_current_username(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    if not payload or "username" not in payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload["username"]


# ======================
# PYDANTIC MODELS
# ======================
class UserCreate(BaseModel):
    username: str
    email: str
    phone: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class PublicKeyUpload(BaseModel):
    username: str
    public_key_jwk: str


class ProfileUpdate(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None
    profile_image: Optional[str] = None


class OtpRequest(BaseModel):
    channel: str
    identifier: str


class OtpVerify(BaseModel):
    channel: str
    identifier: str
    otp: str


OTP_EXPIRY_MINUTES = 5
otp_store: Dict[str, Dict[str, str]] = {}
ALLOW_DEV_OTP_FALLBACK = os.getenv("ALLOW_DEV_OTP_FALLBACK", "true").lower() == "true"


def send_email_otp(recipient_email: str, otp: str):
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_username = os.getenv("SMTP_USERNAME", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_username)

    if not smtp_host or not smtp_username or not smtp_password or not smtp_from:
        raise HTTPException(
            status_code=503,
            detail="Email OTP service is not configured on server"
        )

    subject = "Your CipherChat OTP"
    body = f"Your OTP is {otp}. It expires in {OTP_EXPIRY_MINUTES} minutes."
    message = (
        f"From: {smtp_from}\r\n"
        f"To: {recipient_email}\r\n"
        f"Subject: {subject}\r\n\r\n"
        f"{body}"
    )

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_from, [recipient_email], message)


def send_sms_otp(recipient_phone: str, otp: str):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID", "")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")
    from_phone = os.getenv("TWILIO_FROM_NUMBER", "")

    if not account_sid or not auth_token or not from_phone:
        raise HTTPException(
            status_code=503,
            detail="SMS OTP service is not configured on server"
        )

    payload = urlparse.urlencode({
        "To": recipient_phone,
        "From": from_phone,
        "Body": f"Your CipherChat OTP is {otp}. Valid for {OTP_EXPIRY_MINUTES} minutes."
    }).encode("utf-8")

    credentials = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("utf-8")
    req = urlrequest.Request(
        url=f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
        data=payload,
        method="POST"
    )
    req.add_header("Authorization", f"Basic {credentials}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with urlrequest.urlopen(req) as response:
        if response.status < 200 or response.status >= 300:
            raise HTTPException(status_code=503, detail="Failed to send SMS OTP")


# ======================
# SERVE FRONTEND
# ======================
@app.get("/auth", response_class=HTMLResponse)
def serve_auth():
    with open("auth.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/chat", response_class=HTMLResponse)
def serve_chat():
    with open("chat.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/profile", response_class=HTMLResponse)
def serve_profile():
    with open("profile.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/")
def home():
    return {"message": "Secure Chat API Running"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


# ======================
# AUTH ROUTES
# ======================
@app.post("/register")
def register(user: UserCreate):
    db = SessionLocal()

    existing = db.query(User).filter(
        (User.username == user.username) |
        (User.email == user.email)
    ).first()

    if existing:
        db.close()
        raise HTTPException(status_code=400, detail="Username or Email already exists")

    hashed = hash_password(user.password)

    new_user = User(
        username=user.username,
        email=user.email,
        phone=user.phone,
        password=hashed
    )

    db.add(new_user)
    db.commit()
    db.close()

    return {"message": "Registered successfully"}


@app.post("/login")
def login(user: UserLogin):
    db = SessionLocal()
    db_user = db.query(User).filter(User.username == user.username).first()
    db.close()

    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"username": user.username})
    return {"access_token": token}


@app.post("/request-otp")
def request_otp(payload: OtpRequest):
    channel = payload.channel.strip().lower()
    identifier = payload.identifier.strip()

    if channel not in {"email", "phone"}:
        raise HTTPException(status_code=400, detail="Channel must be 'email' or 'phone'")

    if not identifier:
        raise HTTPException(status_code=400, detail="Email or phone is required")

    if channel == "phone":
        identifier = identifier.replace(" ", "")

    db = SessionLocal()
    if channel == "email":
        user = db.query(User).filter(User.email == identifier).first()
    else:
        user = db.query(User).filter(User.phone == identifier).first()
    db.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found with this email/phone")

    otp = str(secrets.randbelow(900000) + 100000)
    otp_store[user.username] = {
        "otp": otp,
        "channel": channel,
        "identifier": identifier,
        "expires_at": (datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()
    }

    delivery_mode = channel
    dev_otp = None
    try:
        if channel == "email":
            send_email_otp(identifier, otp)
        else:
            send_sms_otp(identifier, otp)
    except HTTPException as ex:
        if ex.status_code == 503 and ALLOW_DEV_OTP_FALLBACK:
            delivery_mode = "dev"
            dev_otp = otp
            print(f"[OTP-DEV] user={user.username} channel={channel} identifier={identifier} otp={otp}")
        else:
            otp_store.pop(user.username, None)
            raise
    except Exception:
        if ALLOW_DEV_OTP_FALLBACK:
            delivery_mode = "dev"
            dev_otp = otp
            print(f"[OTP-DEV] user={user.username} channel={channel} identifier={identifier} otp={otp}")
        else:
            otp_store.pop(user.username, None)
            raise HTTPException(status_code=503, detail="Unable to deliver OTP right now")

    response = {
        "message": "OTP sent successfully",
        "delivery_mode": delivery_mode,
        "expires_in_seconds": OTP_EXPIRY_MINUTES * 60
    }

    if dev_otp:
        response["dev_otp"] = dev_otp

    return response


@app.post("/verify-otp")
def verify_otp(payload: OtpVerify):
    channel = payload.channel.strip().lower()
    identifier = payload.identifier.strip()
    otp = payload.otp.strip()

    if channel not in {"email", "phone"}:
        raise HTTPException(status_code=400, detail="Channel must be 'email' or 'phone'")

    if not identifier or not otp:
        raise HTTPException(status_code=400, detail="Identifier and OTP are required")

    if channel == "phone":
        identifier = identifier.replace(" ", "")

    db = SessionLocal()
    if channel == "email":
        user = db.query(User).filter(User.email == identifier).first()
    else:
        user = db.query(User).filter(User.phone == identifier).first()
    db.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found with this email/phone")

    stored = otp_store.get(user.username)
    if not stored:
        raise HTTPException(status_code=400, detail="No OTP requested. Please request OTP first")

    if stored.get("channel") != channel or stored.get("identifier") != identifier:
        raise HTTPException(status_code=400, detail="OTP request does not match this login method")

    expires_at = datetime.fromisoformat(stored["expires_at"])
    if datetime.utcnow() > expires_at:
        otp_store.pop(user.username, None)
        raise HTTPException(status_code=400, detail="OTP expired. Please request a new OTP")

    if stored["otp"] != otp:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    otp_store.pop(user.username, None)
    token = create_token({"username": user.username})
    return {"access_token": token, "username": user.username}


@app.get("/users")
def get_users(current_username: str = Depends(get_current_username)):
    db = SessionLocal()
    users = db.query(User).all()
    db.close()

    return [
        {
            "username": u.username,
            "email": u.email,
            "phone": u.phone,
            "profile_image": u.profile_image or ""
        }
        for u in users
    ]


@app.get("/me")
def get_me(current_username: str = Depends(get_current_username)):
    db = SessionLocal()
    user = db.query(User).filter(User.username == current_username).first()
    db.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "username": user.username,
        "email": user.email,
        "phone": user.phone,
        "profile_image": user.profile_image or ""
    }


@app.put("/me")
def update_me(payload: ProfileUpdate, current_username: str = Depends(get_current_username)):
    db = SessionLocal()
    user = db.query(User).filter(User.username == current_username).first()

    if not user:
        db.close()
        raise HTTPException(status_code=404, detail="User not found")

    if payload.email is not None and payload.email != user.email:
        email_exists = db.query(User).filter(
            (User.email == payload.email) & (User.username != current_username)
        ).first()
        if email_exists:
            db.close()
            raise HTTPException(status_code=400, detail="Email already in use")
        user.email = payload.email

    if payload.phone is not None:
        user.phone = payload.phone

    if payload.profile_image is not None:
        user.profile_image = payload.profile_image

    db.commit()
    db.refresh(user)
    db.close()

    return {
        "message": "Profile updated",
        "profile": {
            "username": user.username,
            "email": user.email,
            "phone": user.phone,
            "profile_image": user.profile_image or ""
        }
    }


# ======================
# PUBLIC KEY ROUTES (E2EE)
# ======================
@app.post("/public-key")
def upload_public_key(data: PublicKeyUpload):
    db = SessionLocal()

    existing = db.query(PublicKey).filter(PublicKey.username == data.username).first()
    if existing:
        existing.public_key_jwk = data.public_key_jwk
    else:
        new_key = PublicKey(username=data.username, public_key_jwk=data.public_key_jwk)
        db.add(new_key)

    db.commit()
    db.close()

    return {"message": "Public key stored"}


@app.get("/public-key/{username}")
def get_public_key(username: str):
    db = SessionLocal()
    entry = db.query(PublicKey).filter(PublicKey.username == username).first()
    db.close()

    if not entry:
        raise HTTPException(status_code=404, detail="Public key not found")

    return {"username": username, "public_key_jwk": entry.public_key_jwk}


@app.get("/messages/{peer_username}")
def get_conversation(peer_username: str, current_username: str = Depends(get_current_username)):
    db = SessionLocal()
    rows = db.query(Message).filter(
        ((Message.sender == current_username) & (Message.recipient == peer_username)) |
        ((Message.sender == peer_username) & (Message.recipient == current_username))
    ).order_by(Message.id.asc()).all()
    db.close()

    return [
        {
            "id": row.id,
            "sender": row.sender,
            "recipient": row.recipient,
            "ciphertext": row.ciphertext,
            "iv": row.iv,
        }
        for row in rows
    ]


# ======================
# WEBSOCKET — PRIVATE 1-ON-1 MESSAGING
# ======================
connected_clients: Dict[str, WebSocket] = {}


@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    payload = decode_token(token)

    if not payload:
        await websocket.close()
        return

    sender = payload["username"]
    await websocket.accept()
    connected_clients[sender] = websocket

    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)

            recipient = data.get("to")
            ciphertext = data.get("ciphertext", "")
            iv = data.get("iv", "")

            if not recipient:
                continue

            db = SessionLocal()
            db.add(Message(
                sender=sender,
                recipient=recipient,
                ciphertext=ciphertext,
                iv=iv
            ))
            db.commit()
            db.close()

            message_payload = json.dumps({
                "from": sender,
                "ciphertext": ciphertext,
                "iv": iv,
            })

            # Send to recipient if they are online
            if recipient and recipient in connected_clients:
                await connected_clients[recipient].send_text(message_payload)

            # Echo back to sender so they see their own message
            await websocket.send_text(message_payload)

    except WebSocketDisconnect:
        connected_clients.pop(sender, None)