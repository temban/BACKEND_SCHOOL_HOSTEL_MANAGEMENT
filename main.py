from fastapi import FastAPI, HTTPException, Depends, Form, status
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Enum
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.orm import declarative_base
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
import pandas as pd
from fastapi import UploadFile, File
from io import BytesIO
import os
# Database URL
DATABASE_URL = "postgresql://postgres:allpha01@localhost/HosteManagement"

# Create engine
engine = create_engine(DATABASE_URL)

# Create a SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative class definitions
Base = declarative_base()


# Dependency to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# UserCreate model for signup
class UserCreate(BaseModel):
    email: str
    username: str
    disable: bool = False
    phone: str = None
    password: str
    role: str = "admin"


# User model
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, index=True)
    disable = Column(Boolean, default=False)
    phone = Column(String)
    password = Column(String)
    role = Column(String, default="admin")

    # Relationship with School table
    schools = relationship("School", back_populates="user")


# School model
class School(Base):
    __tablename__ = 'schools'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    country = Column(String)  # Added country column
    city = Column(String)  # Added city column
    state = Column(String)  # Added state column
    matricule = Column(String)  # Added matricule column
    location = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))  # ForeignKey relationship

    # Relationship with User and school table
    user = relationship("User", back_populates="schools")
    managers = relationship("Manager", back_populates="school")


# Manager model
class Manager(Base):
    __tablename__ = 'managers'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    phone = Column(String)
    password = Column(String)
    school_id = Column(Integer, ForeignKey('schools.id'))

    # Relationship with School table
    school = relationship("School", back_populates="managers")


# Pydantic models for data validation
class ManagerCreate(BaseModel):
    name: str
    email: str
    phone: str
    password: str
    school_id: int


class ManagerUpdate(BaseModel):
    name: str
    email: str
    phone: str


class ManagerUpdatePassword(BaseModel):
    password: str
    confirm_password: str


class ManagerLogin(BaseModel):
    email: str
    password: str


# Dormitory model
class Dom(Base):
    __tablename__ = 'doms'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    manager_id = Column(Integer, ForeignKey('managers.id'))
    gender = Column(Enum('male', 'female', name='gender'), nullable=False)

    # Relationship with Manager table
    manager = relationship("Manager", back_populates="doms")


# Update the Manager model to include the relationship with Dom
Manager.doms = relationship("Dom", back_populates="manager")


# Pydantic models for data validation
class DomCreate(BaseModel):
    name: str
    manager_id: int


class DomUpdate(BaseModel):
    name: str

# Student model
class Student(Base):
    __tablename__ = 'students'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    gender = Column(Enum('male', 'female', name='gender'), nullable=False)
    class_room = Column(String, index=True)
    matricule = Column(String, index=True)
    dom_id = Column(Integer, ForeignKey('doms.id'))

    # Relationship with Dom table
    dom = relationship("Dom", back_populates="students")


# Update the Dom model to include the relationship with Student
Dom.students = relationship("Student", back_populates="dom")


# Pydantic models for data validation
class StudentCreate(BaseModel):
    name: str
    class_room: str
    matricule: str
    dom_id: int


class StudentUpdate(BaseModel):
    name: str
    class_room: str
    matricule: str


# Create tables in the database
Base.metadata.create_all(bind=engine)


# Utility functions
def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# FastAPI instance
app = FastAPI()


# Signup route
@app.post("/signup")
async def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    # Hash the password before storing it in the database
    hashed_password = pwd_context.hash(user_data.password)
    # Create a new user instance
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        password=hashed_password,
        disable=user_data.disable,
        phone=user_data.phone,
        role=user_data.role
    )
    # Add the new user to the session and commit the transaction
    db.add(new_user)
    db.commit()
    return {"user_id": new_user.id}


# Login route
@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Query the database for the user with the provided email
    user = db.query(User).filter(User.email == email).first()

    # Check if user exists and password is correct
    if not user or not pwd_context.verify(password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Return token and user object
    return {"access_token": "generate_random_token()", "user": user}


# CRUD endpoints for School

# Create school
@app.post("/create/schools/")
async def create_school(name: str, location: str, country: str, state: str, city: str, matricule: str, user_id: int,
                        db: Session = Depends(get_db)):
    # Check if user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Create a new school instance
    new_school = School(name=name, location=location, user_id=user_id, country=country, state=state, city=city,
                        matricule=matricule)

    # Add the new school to the session and commit the transaction
    db.add(new_school)
    db.commit()
    db.refresh(new_school)

    return new_school


# Read school
@app.get("/get/schools/{school_id}")
async def read_school(school_id: int, db: Session = Depends(get_db)):
    school = db.query(School).filter(School.id == school_id).first()
    if not school:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="School not found")
    return school


@app.get("/schools/by_user/{user_id}")
async def get_schools_by_user(user_id: int, db: Session = Depends(get_db)):
    schools = db.query(School).filter(School.user_id == user_id).all()
    if not schools:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No schools found for this user")
    return schools


# Update school
@app.put("/update/schools/{school_id}")
async def update_school(school_id: int, name: str, location: str, country: str, state: str, city: str, matricule: str,
                        db: Session = Depends(get_db)):
    school = db.query(School).filter(School.id == school_id).first()
    if not school:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="School not found")
    school.name = name
    school.location = location
    school.country = country
    school.state = state
    school.city = city
    school.matricule = matricule
    db.commit()
    return {"message": "School updated successfully"}


# Delete school
@app.delete("/delete/schools/{school_id}")
async def delete_school(school_id: int, db: Session = Depends(get_db)):
    school = db.query(School).filter(School.id == school_id).first()
    if not school:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="School not found")
    db.delete(school)
    db.commit()
    return {"message": "School deleted successfully"}


@app.post("/create/managers/", response_model=ManagerCreate)
def create_manager(manager: ManagerCreate, db: Session = Depends(get_db)):
    # Check if the manager's email already exists
    existing_manager = db.query(Manager).filter(Manager.email == manager.email).first()
    if existing_manager:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

    # Check if the provided school ID exists
    school = db.query(School).filter(School.id == manager.school_id).first()
    if not school:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="School ID does not exist")

    hashed_password = get_password_hash(manager.password)
    db_manager = Manager(
        name=manager.name,
        email=manager.email,
        phone=manager.phone,
        password=hashed_password,
        school_id=manager.school_id
    )
    db.add(db_manager)
    db.commit()
    db.refresh(db_manager)
    return db_manager


# Read Manager by ID
@app.get("/get/manager/{manager_id}")
async def read_manager(manager_id: int, db: Session = Depends(get_db)):
    manager = db.query(Manager).filter(Manager.id == manager_id).first()
    if not manager:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Manager not found")
    return manager


# Get Managers by School
@app.get("/managers/by_school/{school_id}")
async def get_managers_by_school(school_id: int, db: Session = Depends(get_db)):
    managers = db.query(Manager).filter(Manager.school_id == school_id).all()
    if not managers:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No managers found for this school")
    return managers


# Update Manager
@app.put("/update/manager/{manager_id}")
async def update_manager(manager_id: int, manager_update: ManagerUpdate, db: Session = Depends(get_db)):
    manager = db.query(Manager).filter(Manager.id == manager_id).first()
    if not manager:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Manager not found")
    manager.name = manager_update.name
    manager.email = manager_update.email
    manager.phone = manager_update.phone
    db.commit()
    return {"message": "Manager updated successfully"}


# Delete Manager
@app.delete("/delete/managers/{manager_id}")
async def delete_manager(manager_id: int, db: Session = Depends(get_db)):
    manager = db.query(Manager).filter(Manager.id == manager_id).first()
    if not manager:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Manager not found")
    db.delete(manager)
    db.commit()
    return {"message": "Manager deleted successfully"}


# Manager Login
@app.post("/manager/login")
async def login_manager(manager_login: ManagerLogin, db: Session = Depends(get_db)):
    manager = db.query(Manager).filter(Manager.email == manager_login.email).first()
    if not manager or not verify_password(manager_login.password, manager.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    return manager


@app.put("/manager/new/password/{manager_id}", response_model=ManagerUpdatePassword)
def update_manager_password(manager_id: int, manager_update: ManagerUpdatePassword, db: Session = Depends(get_db)):
    db_manager = db.query(Manager).filter(Manager.id == manager_id).first()
    if not db_manager:
        raise HTTPException(status_code=404, detail="Manager not found")
    db_manager.password = get_password_hash(manager_update.password)
    db.commit()
    db.refresh(db_manager)
    return db_manager


# Create Dom
@app.post("/create/dom/", response_model=DomCreate)
def create_dom(dom: DomCreate, db: Session = Depends(get_db)):
    # Check if the provided manager ID exists
    manager = db.query(Manager).filter(Manager.id == dom.manager_id).first()
    if not manager:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manager ID does not exist")

    db_dom = Dom(
        name=dom.name,
        gender=dom.gender,
        manager_id=dom.manager_id
    )
    db.add(db_dom)
    db.commit()
    db.refresh(db_dom)
    return db_dom


# Read Dom by ID
@app.get("/get/dom/{dom_id}")
async def read_dom(dom_id: int, db: Session = Depends(get_db)):
    dom = db.query(Dom).filter(Dom.id == dom_id).first()
    if not dom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dom not found")
    return dom


# Get Doms by Manager
@app.get("/doms/by_manager/{manager_id}")
async def get_doms_by_manager(manager_id: int, db: Session = Depends(get_db)):
    doms = db.query(Dom).filter(Dom.manager_id == manager_id).all()
    if not doms:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No doms found for this manager")
    return doms


# Update Dom
@app.put("/update/dom/{dom_id}")
async def update_dom(dom_id: int, dom_update: DomUpdate, db: Session = Depends(get_db)):
    dom = db.query(Dom).filter(Dom.id == dom_id).first()
    if not dom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dom not found")
    dom.name = dom_update.name,
    dom.gender = dom.gender
    db.commit()
    return {"message": "Dom updated successfully"}


# Delete Dom
@app.delete("/delete/dom/{dom_id}")
async def delete_dom(dom_id: int, db: Session = Depends(get_db)):
    dom = db.query(Dom).filter(Dom.id == dom_id).first()
    if not dom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dom not found")
    db.delete(dom)
    db.commit()
    return {"message": "Dom deleted successfully"}


# Create Student
@app.post("/create/student/", response_model=StudentCreate)
def create_student(student: StudentCreate, db: Session = Depends(get_db)):
    # Check if the provided dom ID exists
    dom = db.query(Dom).filter(Dom.id == student.dom_id).first()
    if not dom:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Dom ID does not exist")

    db_student = Student(
        name=student.name,
        gender=student.gender,
        class_room=student.class_room,
        matricule=student.matricule,
        dom_id=student.dom_id
    )
    db.add(db_student)
    db.commit()
    db.refresh(db_student)
    return db_student


# Read Student by ID
@app.get("/get/student/{student_id}")
async def read_student(student_id: int, db: Session = Depends(get_db)):
    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student not found")
    return student


# Get Students by Dom
@app.get("/get/students/by_dom/{dom_id}")
async def get_students_by_dom(dom_id: int, db: Session = Depends(get_db)):
    students = db.query(Student).filter(Student.dom_id == dom_id).all()
    if not students:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No students found for this dom")
    return students


# Update Student
@app.put("/update/student/{student_id}")
async def update_student(student_id: int, student_update: StudentUpdate, db: Session = Depends(get_db)):
    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student not found")
    student.name = student_update.name
    student.gender = student_update.gender,
    student.class_room = student_update.class_room
    student.matricule = student_update.matricule
    db.commit()
    return {"message": "Student updated successfully"}


# Delete Student
@app.delete("/delete/student/{student_id}")
async def delete_student(student_id: int, db: Session = Depends(get_db)):
    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student not found")
    db.delete(student)
    db.commit()
    return {"message": "Student deleted successfully"}


@app.post("/students/upload/{dom_id}")
async def upload_students(dom_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Check if the provided dom ID exists
    dom = db.query(Dom).filter(Dom.id == dom_id).first()
    if not dom:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Dom ID does not exist")

    # Read the Excel file
    try:
        contents = await file.read()
        file_extension = os.path.splitext(file.filename)[1]

        if file_extension == '.xls':
            df = pd.read_excel(BytesIO(contents), engine='xlrd')
        elif file_extension == '.xlsx':
            df = pd.read_excel(BytesIO(contents), engine='openpyxl')
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid file format")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error reading file: {str(e)}")

    # Validate the file contents
    required_columns = {"name", "class_room", "matricule"}
    if not required_columns.issubset(df.columns):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"File must contain columns: {required_columns}")

    # Add students to the database
    students = []
    for _, row in df.iterrows():
        # Check if the student already exists
        existing_student = db.query(Student).filter(
            Student.matricule == row['matricule'],
            Student.dom_id == dom_id
        ).first()

        if existing_student:
            # Skip or handle existing student case
            continue  # Skipping for this example

        student = Student(
            name=row['name'],
            class_room=row['class_room'],
            matricule=row['matricule'],
            dom_id=dom_id
        )
        db.add(student)
        students.append(student)

    db.commit()
    for student in students:
        db.refresh(student)

    return {"message": "Students uploaded successfully"}