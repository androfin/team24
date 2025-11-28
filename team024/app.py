"""Main Flask application for File Integrity Monitoring System"""
import os
import secrets
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
flask_secret = os.environ.get("FLASK_SECRET_KEY")
if not flask_secret:
    flask_secret = secrets.token_hex(32)
    print("[SECURITY] Generated random Flask secret key for this session")
app.secret_key = flask_secret
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

from routes import register_routes
register_routes(app)

with app.app_context():
    import models
    db.create_all()
    print("[DB] PostgreSQL database tables created successfully")
