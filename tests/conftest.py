import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set test environment variables before importing app modules
os.environ["DATABASE_URL"] = "sqlite:///./test_agent.db"
os.environ["MODEL_API_KEY"] = "mock-test-key"
os.environ["MODEL_BASE_URL"] = "https://mock.api/v1"
os.environ["MODEL_NAME"] = "gpt-4o-mini"

from app.database import Base, get_db
from app.main import app


@pytest.fixture
def test_db_session():
    # File-backed test db for persistence and restart testing
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db_url = f"sqlite:///{path}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    yield {
        "engine": engine,
        "SessionLocal": TestingSessionLocal,
        "path": path,
    }

    app.dependency_overrides.clear()
    engine.dispose()
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


@pytest.fixture
def client(test_db_session):
    return TestClient(app)
