import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base, get_db
from main import app, window_buffer
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_shared.db"

engine = create_engine("sqlite:///./test_shared.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def reset_db_state():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    window_buffer.clear()
    yield
    Base.metadata.drop_all(bind=engine)
