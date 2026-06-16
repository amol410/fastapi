from fastapi import FastAPI, Request, Form, Depends, Response, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, String, select, Float
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
import shutil
from typing import Optional

# ==========================================
# 1. SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "my_super_secret_key_for_development" # In production, keep this safe!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Directory for uploaded images
UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

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
    hashed_password: Mapped[str] = mapped_column(String(100))

class Product(Base):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(200))
    price: Mapped[str] = mapped_column(String(20)) # Using string for flexibility (e.g. "$19.99")
    image_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
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
    existing_user = db.scalars(select(User).where(User.email == email)).first()
    if existing_user:
        return templates.TemplateResponse(request=request, name="signup.html", context={"error": "Email already registered."})
    
    new_user = User(name=name, email=email, hashed_password=get_password_hash(password))
    db.add(new_user)
    db.commit()
    
    access_token = create_access_token(data={"sub": new_user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.scalars(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid email or password."})
    
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
# 5. PROTECTED ROUTES (CRUD for Products)
# ==========================================

@app.get("/", response_class=HTMLResponse)
def home_page(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
        
    products = db.scalars(select(Product)).all()
    return templates.TemplateResponse(
        request=request, 
        name="index.html", 
        context={"products": products, "current_user": current_user}
    )

@app.get("/create", response_class=HTMLResponse)
def create_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="create.html")

@app.post("/create")
async def create_product(
    name: str = Form(...), 
    description: str = Form(...), 
    price: str = Form(...), 
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    
    image_path = None
    if image and image.filename:
        file_extension = os.path.splitext(image.filename)[1]
        unique_filename = f"{datetime.now().timestamp()}{file_extension}"
        image_path = f"uploads/{unique_filename}"
        with open(os.path.join(UPLOAD_DIR, unique_filename), "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)

    new_product = Product(name=name, description=description, price=price, image_path=image_path)
    db.add(new_product)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/update/{product_id}", response_class=HTMLResponse)
def update_page(request: Request, product_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    product = db.get(Product, product_id)
    return templates.TemplateResponse(request=request, name="update.html", context={"product": product})

@app.post("/update/{product_id}")
async def update_product(
    product_id: int, 
    name: str = Form(...), 
    description: str = Form(...), 
    price: str = Form(...), 
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    
    product = db.get(Product, product_id)
    if product:
        product.name = name
        product.description = description
        product.price = price
        
        if image and image.filename:
            # Delete old image if it exists
            if product.image_path:
                old_path = os.path.join("static", product.image_path)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            file_extension = os.path.splitext(image.filename)[1]
            unique_filename = f"{datetime.now().timestamp()}{file_extension}"
            product.image_path = f"uploads/{unique_filename}"
            with open(os.path.join(UPLOAD_DIR, unique_filename), "wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
                
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/delete/{product_id}")
def delete_product(product_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    product = db.get(Product, product_id)
    if product:
        if product.image_path:
            old_path = os.path.join("static", product.image_path)
            if os.path.exists(old_path):
                os.remove(old_path)
        db.delete(product)
        db.commit()
    return RedirectResponse(url="/", status_code=303)