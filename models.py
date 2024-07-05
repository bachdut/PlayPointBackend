from datetime import datetime
from dbModel import db
from sqlalchemy import Column, DateTime, Boolean

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    google_id = db.Column(db.String(256), nullable=True)
    profile_picture = db.Column(db.String(256), nullable=True)
    full_name = db.Column(db.String(100), nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    favorite_sport = db.Column(db.String(50), nullable=True)
    professional_level = db.Column(db.String(50), nullable=True)
    favorite_position = db.Column(db.String(50), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    health_declaration = db.Column(db.Boolean, nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username}>"

class Court(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<Court {self.name}, Location: {self.location}>"

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    court_id = db.Column(db.Integer, db.ForeignKey('court.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_name = db.Column(db.String(120), nullable=False)
    court_name = db.Column(db.String(120), nullable=False)
    reserved_seat = db.Column(db.Integer, nullable=False)
    reserved_on = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship('User', backref=db.backref('reservations', lazy='dynamic'))
    court = db.relationship('Court', backref=db.backref('reservations', lazy='dynamic'))

    def __repr__(self):
        return f'<Reservation {self.user_name} for {self.court_name}>'
    
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class GroupingProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    original_price = db.Column(db.Float, nullable=False)
    discount_rate = db.Column(db.Float, nullable=False)
    total_needed = db.Column(db.Integer, nullable=False)
    current_participants = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Product {self.name}>'
    
class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)