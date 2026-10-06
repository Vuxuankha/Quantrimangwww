# PostgreSQL migration scaffold (v1.9)

The current NMS modules still access SQLite directly through `database.db`. Do not flip production to PostgreSQL yet.

Migration sequence:
1. Freeze schema changes in legacy SQLite modules.
2. Introduce SQLAlchemy repositories behind the FastAPI services.
3. Create Alembic migrations for users, assets, security events, incidents, vulnerabilities, patches, compliance and audit.
4. Run dual-read comparison in staging.
5. Perform one-time SQLite -> PostgreSQL data copy and validate row counts/checksums.
6. Switch API reads/writes to PostgreSQL.
7. Migrate background NMS workers last.

`deploy/docker-compose.yml` provides PostgreSQL and Redis for development/staging only. Change all credentials before deployment.
