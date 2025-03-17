# models.py (Updated Database Models with Foreign Keys & Auto-update Timestamps)
from extensions import db
from sqlalchemy.sql import func
import datetime

class User(db.Model):
    __tablename__ = 'users'  # Explicitly set the table name
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    dob = db.Column(db.Date)
    profile_image = db.Column(db.String(255), nullable=True)
    last_active = db.Column(db.DateTime)
    # Add cursor tracking fields
    cursor_x = db.Column(db.Integer)
    cursor_y = db.Column(db.Integer)
    last_cursor_move = db.Column(db.DateTime)
    # Add activity status
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    leads = db.relationship('Lead', backref='assigned_user', lazy=True)
    followups = db.relationship('Followup', backref='staff', lazy=True)
    account_opens = db.relationship('AccountOpen', backref='staff', lazy=True)
    sales = db.relationship('Sale', backref='staff', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

class MetaFetchTimestamp(db.Model):
    __tablename__ = 'meta_fetch_timestamps'
    
    id = db.Column(db.Integer, primary_key=True)
    last_fetched = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Lead(db.Model):
    __tablename__ = 'leads'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    city = db.Column(db.String(100), nullable=True)  # Adding city field
    source = db.Column(db.String(50), nullable=False)  # 'csv_import', 'meta_ads', 'manual', etc.
    status = db.Column(db.String(20), nullable=False, default='new')  # 'new', 'contacted', 'qualified', 'converted', etc.
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    assigned_staff_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Additional fields for Meta Ads leads
    meta_form_id = db.Column(db.String(100), nullable=True)
    meta_lead_id = db.Column(db.String(100), nullable=True)
    meta_campaign = db.Column(db.String(100), nullable=True)
    
    # Relationships
    followups = db.relationship('Followup', backref='lead', lazy=True)
    assigned_staff = db.relationship('User', backref=db.backref('assigned_leads', overlaps="leads"), overlaps="leads")
    account_opens = db.relationship('AccountOpen', backref='lead', lazy=True)
    sales = db.relationship('Sale', backref='lead', lazy=True)

    def __init__(self, name, email, phone, source, status='new', city=None, assigned_staff_id=None):
        self.name = name
        self.email = email
        self.phone = phone
        self.city = city
        self.source = source
        self.status = status
        self.assigned_staff_id = assigned_staff_id

class Followup(db.Model):
    __tablename__ = 'followups'
    
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('leads.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    followup_date = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.Text, nullable=True)

class AccountOpen(db.Model):
    __tablename__ = 'account_opens'
    
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('leads.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    open_date = db.Column(db.DateTime, nullable=False)

class Sale(db.Model):
    __tablename__ = 'sales'
    
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('leads.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sale_date = db.Column(db.DateTime, nullable=False)
    amount = db.Column(db.Float, nullable=False)
