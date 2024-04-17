from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class Note(db.Model):#BankNOTES
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Integer)#account-data
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(400))
    first_name = db.Column(db.String(150))
    salt = db.Column(db.String(100))
    failed_login = db.Column(db.Integer)
    logged_on = db.Column(db.String(100))
    notes = db.relationship('Note')
    logged = db.relationship('Logg')

class Logg(db.Model):
    logg_id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(300))
    time = db.Column(db.DateTime(timezone = True), default = func.now())#tidsonen er totimer bak CET
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
