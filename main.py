from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Depends, Query
import shutil, bcrypt, jwt
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import JWTError
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, Session ,declarative_base

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    name = Column(String, nullable=True)
    mobile = Column(String, nullable=True)
    gender = Column(String, nullable=True)
    location = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_token(email: str):
    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def authenticate_user(token: str = Query(...)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.post("/signup")
def signup(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail={"status":0, "Message":"Email already exists"})
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user = User(email=email, password=hashed_password.decode())
    db.add(user)
    db.commit() 
    token = create_token(email)
    return {"status":1,"message": "User registered successfully","token": token}

@app.post("/login/email={email}&password={password}")
def login(email: str, password: str, db: Session = Depends(get_db),token: str = Depends(oauth2_scheme)):
    user = db.query(User).filter(User.email == email).first()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not user or not bcrypt.checkpw(password.encode(), user.password.encode()):
            raise HTTPException(status_code=401, detail="Invalid credentials & Token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid")
    return {"status": 1,"message":"Logged in successfully"}

@app.post("/upload")
def upload_file(id: int = Form(...), name: str = Form(...), email: str = Form(...), mobile: str = Form(...),
                gender: str = Form(...), location: str = Form(...), file: UploadFile = File(...),
             db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail={"status":0,"message":" User not found"})
        
        with open(f"uploaded_{file.filename}", "wb") as f:
            shutil.copyfileobj(file.file, f)
            token = create_token(email)
        return {"status":1,"id": id, "name": name, "email": email, "mobile": mobile, "gender": gender,
                "location": location, "filename": file.filename, "message": "File uploaded successfully!",
                     "token": token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/parse-data")
def parse_data(query: str = Query(...), token_data: dict = Depends(authenticate_user)):
    return {"query_received": query}
