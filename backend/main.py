import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import bcrypt

from database import Base, engine, get_db
from models import Note, User

Base.metadata.create_all(bind=engine)

app = FastAPI()


from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class NoteCreate(BaseModel):
    title: str
    content: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/notes")
def create_note(data: NoteCreate, db: Session = Depends(get_db)):
    note = Note(title=data.title, content=data.content)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@app.get("/notes")
def list_notes(db: Session = Depends(get_db)):
    return db.query(Note).all()

@app.get("/notes/{note_id}")
def get_note(note_id: int, db: Session = Depends(get_db)):
    note = db.query(Note).filter(Note.id == note_id).first()
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return note


@app.put("/notes/{note_id}")
def update_note(note_id: int, data: NoteCreate, db: Session = Depends(get_db)):
    note = db.query(Note).filter(Note.id == note_id).first()
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    note.title = data.title
    note.content = data.content
    db.commit()
    db.refresh(note)
    return note


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, db: Session = Depends(get_db)):
    note = db.query(Note).filter(Note.id == note_id).first()
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    db.delete(note)
    db.commit()
    return {"deleted": note_id}


class UserCreate(BaseModel):
    email: str
    password: str


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


SECRET_KEY = "dev-secret-change-later"


class LoginData(BaseModel):
    email: str
    password: str


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