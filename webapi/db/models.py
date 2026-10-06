"""SQLAlchemy 2.x models introduced for the staged PostgreSQL migration.

v2.0 intentionally does not redirect legacy NMS tables to PostgreSQL yet. New web-native
models can be added here and migrated with Alembic without breaking the desktop/NMS path.
"""
try:
    from sqlalchemy.orm import DeclarativeBase
    class Base(DeclarativeBase): pass
except Exception:
    class Base: pass
