from sqlalchemy import (
    MetaData,
    Table,
    Column,
    Integer,
    String,
)


def install(engine):
    meta = MetaData()

    Table(
        "portals",
        meta,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("name", String),
    )

    Table(
        "credentials",
        meta,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("portal_id", Integer),
        Column("login", String),
        Column("password", String),
    )
    meta.create_all(engine)
