from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
import os
from dotenv import load_dotenv

from database import Base, engine, get_db
from models import Note, User

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing. Create backend/.env first.")
bearer = HTTPBearer()


# ---------- Request shapes ----------

class NoteCreate(BaseModel):
    title: str
    content: str


class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=8)


class LoginData(BaseModel):
    email: str
    password: str


# ---------- Helper: who is making this request? ----------

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


# ---------- Public endpoints ----------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/signup")
def signup(data: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    user = User(email=data.email, password_hash=hashed)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "email": user.email}


@app.post("/login")
def login(data: LoginData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if user is None or not bcrypt.checkpw(
        data.password.encode(), user.password_hash.encode()
    ):
        raise HTTPException(status_code=401, detail="Wrong email or password")
    token = jwt.encode(
        {
            "sub": str(user.id),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        SECRET_KEY,
        algorithm="HS256",
    )
    return {"access_token": token}


# ---------- Protected endpoints (need a token) ----------

@app.post("/notes")
def create_note(
    data: NoteCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    note = Note(title=data.title, content=data.content, user_id=user.id)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@app.get("/notes")
def list_notes(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    return db.query(Note).filter(Note.user_id == user.id).all()


@app.get("/notes/{note_id}")
def get_note(
    note_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    note = (
        db.query(Note).filter(Note.id == note_id, Note.user_id == user.id).first()
    )
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return note


@app.put("/notes/{note_id}")
def update_note(
    note_id: int,
    data: NoteCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    note = (
        db.query(Note).filter(Note.id == note_id, Note.user_id == user.id).first()
    )
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    note.title = data.title
    note.content = data.content
    db.commit()
    db.refresh(note)
    return note


@app.delete("/notes/{note_id}")
def delete_note(
    note_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    note = (
        db.query(Note).filter(Note.id == note_id, Note.user_id == user.id).first()
    )
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    db.delete(note)
    db.commit()
    return {"deleted": note_id}