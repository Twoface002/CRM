# models.py (Updated Database Models with Foreign Keys & Auto-update Timestamps)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')
    name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    dob = db.Column(db.String(20), nullable=True)
    profile_image = db.Column(db.String(255), nullable=True)
    last_active = db.Column(db.DateTime, default=func.now(), onupdate=func.now())

    leads = db.relationship('Lead', backref='assigned_user', lazy=True)

class MetaFetchTimestamp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    last_fetched = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.String(50), unique=True, nullable=False)
    created_time = db.Column(db.String(50), nullable=False)
    assigned_staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data = db.Column(db.Text, nullable=False)

class Followup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followup_date = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.Text, nullable=True)

class AccountOpen(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    open_date = db.Column(db.DateTime, nullable=False)

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sale_date = db.Column(db.DateTime, nullable=False)
    amount = db.Column(db.Float, nullable=False)
