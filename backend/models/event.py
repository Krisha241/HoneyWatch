from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import settings

engine = create_engine(
    settings.database_url,
    pool_size=10,        # max persistent connections
    max_overflow=20,     # extra connections allowed under load
    pool_pre_ping=True,  # test connection before using — survives DB restarts
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency injection.
    Yields one DB session per request, always closes on exit.

    Usage:
        @router.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()