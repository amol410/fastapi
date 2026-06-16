from fastapi import FastAPI, Request, Form, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone

# ==========================================
# 1. SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "my_super_secret_key_for_development" # In production, keep this safe!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# We use bcrypt directly to avoid compatibility issues with passlib on newer Python versions
def verify_password(plain_password, hashed_password):
    # Truncate to 72 bytes to match bcrypt algorithm limit and avoid ValueError
    return bcrypt.checkpw(plain_password.encode('utf-8')[:72], hashed_password.encode('utf-8'))

def get_password_hash(password):
    # Truncate to 72 bytes to match bcrypt algorithm limit and avoid ValueError
    return bcrypt.hashpw(password.encode('utf-8')[:72], bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 2. DATABASE SETUP
# ==========================================
engine = create_engine("sqlite:///final_app.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(30))
    email: Mapped[str] = mapped_column(String(50), unique=True)
    # NEW COLUMN: We store the hashed password, never the real one
    hashed_password: Mapped[str] = mapped_column(String(100))

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI()
# NOTE: Matching the capital 'F' from your screenshot
templates = Jinja2Templates(directory="Frontend") 

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# The Guard: This function checks the user's cookies for a valid JWT
def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except jwt.InvalidTokenError:
        return None
    
    # If the token is valid, find the user in the database
    user = db.scalars(select(User).where(User.email == email)).first()
    return user

# ==========================================
# 4. AUTHENTICATION ROUTES (Login/Signup)
# ==========================================

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html")

@app.post("/signup")
def signup_post(request: Request, name: str = Form(...), email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.scalars(select(User).where(User.email == email)).first()
    if existing_user:
        return templates.TemplateResponse(request=request, name="signup.html", context={"error": "Email already registered."})
    
    # Create new user with HASHED password
    new_user = User(name=name, email=email, hashed_password=get_password_hash(password))
    db.add(new_user)
    db.commit()
    
    # Generate JWT and create cookie
    access_token = create_access_token(data={"sub": new_user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Verify user exists and password is correct
    user = db.scalars(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid email or password."})
    
    # Generate JWT and create cookie
    access_token = create_access_token(data={"sub": user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response

# ==========================================
# 5. PROTECTED ROUTES (CRUD)
# ==========================================

@app.get("/", response_class=HTMLResponse)
def home_page(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # If there is no current user (invalid or missing JWT), kick them to the login page
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
        
    users = db.scalars(select(User)).all()
    return templates.TemplateResponse(
        request=request, 
        name="index.html", 
        context={"users": users, "current_user": current_user}
    )

@app.get("/create", response_class=HTMLResponse)
def create_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="create.html")

@app.post("/create")
def create_user(name: str = Form(...), email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # We now require a password when creating users from the dashboard too
    new_user = User(name=name, email=email, hashed_password=get_password_hash(password))
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/update/{user_id}", response_class=HTMLResponse)
def update_page(request: Request, user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    user = db.get(User, user_id)
    return templates.TemplateResponse(request=request, name="update.html", context={"user": user})

@app.post("/update/{user_id}")
def update_user(user_id: int, name: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user:
        user.name = name
        user.email = email
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/delete/{user_id}")
def delete_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    user = db.get(User, user_id)
    if user:
        db.delete(user)
        db.commit()
    # Log out the user if they delete themselves
    if current_user.id == user_id:
        return RedirectResponse(url="/logout", status_code=303)
    return RedirectResponse(url="/", status_code=303)