from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from DBC.database import get_db
from sqlalchemy import text
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer

import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# Secret key for JWT
SECRET_KEY = os.getenv("KEY")  # Change this to a strong secret key
ALGORITHM = os.getenv("ALGORITHM")  # Algorithm for JWT encoding
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("TOKEN")  # Token expiration time in minutes

def hash_password(password: str) -> str:
    """Hash the password using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """Verify hashed password"""
    return pwd_context.verify(plain_password, hashed_password)

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for JWT
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Pydantic models for user input validation
class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

@app.get("/")
def root():
    return {"message": "FastAPI with PostgreSQL is running!"}

@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    """Fetch all users from the database"""
    query = text("SELECT email, password FROM users;")  # Select only email & password
    result = db.execute(query)
    users = result.fetchall()
    return {"users": [dict(row._mapping) for row in users]}  # Convert to JSON

@app.post("/add_users")
def add_user(user: UserCreate, db: Session = Depends(get_db)):
    """Add a new user with hashed password"""
    hashed_password = hash_password(user.password)  # Hash the password
    query = text("INSERT INTO users (email, password) VALUES (:email, :password);")
    db.execute(query, {"email": user.email, "password": hashed_password})
    db.commit()
    return {"message": "User added successfully"}

@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token"""
    query = text("SELECT password FROM users WHERE email = :email;")
    result = db.execute(query, {"email": user.email})
    user_record = result.fetchone()

    if not user_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    stored_hashed_password = user_record.password
    if not verify_password(user.password, stored_hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Generate JWT token
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Generate JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Decode JWT token and get current user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        return email  # Return user email
    except JWTError:
        raise credentials_exception

@app.get("/protected-route")
def protected_route(current_user: str = Depends(get_current_user)):
    """Protected route, accessible only with a valid JWT token"""
    return {"message": f"Welcome, {current_user}! You have access to this route."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
