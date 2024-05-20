from datetime import datetime
from dbModel import db
from sqlalchemy import Column 

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"

class Court(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<Court {self.name}, Location: {self.location}>"


from sqlalchemy import Column, DateTime  # Import the DateTime class

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    court_id = db.Column(db.Integer, db.ForeignKey('court.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_name = db.Column(db.String(120), nullable=False)
    court_name = db.Column(db.String(120), nullable=False)
    reserved_seat = db.Column(db.Integer, nullable=False)
    reserved_on = Column(DateTime, default=datetime.utcnow, nullable=False)  # Fix this line

    user = db.relationship('User', backref=db.backref('reservations', lazy='dynamic'))
    court = db.relationship('Court', backref=db.backref('reservations', lazy='dynamic'))

    def __repr__(self):
        return f'<Reservation {self.user.username} for {self.court.name}>'

