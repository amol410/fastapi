from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

# ==========================================
# 1. DATABASE SETUP
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

Base.metadata.create_all(bind=engine)

# ==========================================
# 2. FASTAPI & JINJA2 SETUP
# ==========================================
app = FastAPI()
templates = Jinja2Templates(directory="frontend")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 3. ROUTES (Returning HTML Pages)
# ==========================================

# --- READ (Homepage) --- http://127.0.0.1:8000/
@app.get("/", response_class=HTMLResponse)
def home_page(request: Request, db: Session = Depends(get_db)):
    users = db.scalars(select(User)).all()
    return templates.TemplateResponse(
        request=request, 
        name="index.html", 
        context={"users": users}
    )

# --- CREATE --- http://127.0.0.1:8000/create
@app.get("/create", response_class=HTMLResponse)
def create_page(request: Request):
    return templates.TemplateResponse(request=request, name="create.html")

@app.post("/create")
def create_user(name: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    new_user = User(name=name, email=email)
    db.add(new_user)
    db.commit()
    # 303 status code tells the browser to redirect back to the homepage
    return RedirectResponse(url="/", status_code=303)

# --- UPDATE ---
@app.get("/update/{user_id}", response_class=HTMLResponse)
def update_page(request: Request, user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    return templates.TemplateResponse(
        request=request, 
        name="update.html", 
        context={"user": user}
    )

@app.post("/update/{user_id}")
def update_user(user_id: int, name: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user:
        user.name = name
        user.email = email
        db.commit()
    return RedirectResponse(url="/", status_code=303)

# --- DELETE ---
@app.get("/delete/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user:
        db.delete(user)
        db.commit()
    return RedirectResponse(url="/", status_code=303)


# pip install python-multipart
"""extracts the file and form fields 
so your code can actually use them."""

# pip install jinja2
"""Jinja2 is a templating engine for Python"""