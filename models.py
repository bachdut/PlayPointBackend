from datetime import datetime
from dbModel import db
from sqlalchemy import Column, DateTime, Boolean
import json

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
    reservations = db.relationship('Reservation', backref='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"

import json
from sqlalchemy import Column, Integer, String, Float, Text

class Court(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False, default=0.0)
    time_slots = db.Column(db.Text, nullable=True)  # Store available time slots as JSON string
    image = db.Column(db.String(200), nullable=True)
    level_of_players = db.Column(db.String(50), nullable=True, default='Beginner')
    category = db.Column(db.String(50), nullable=True, default='General')
    players_joined = db.Column(db.Integer, nullable=False, default=0)

    def __repr__(self):
        return f"Court('{self.name}', '{self.location}', '{self.price}', '{self.time_slots}', '{self.image}', '{self.available_seats}', '{self.level_of_players}', '{self.category}', '{self.players_joined}')"

    def set_time_slots(self, date, slots):
        """Set time slots for a specific date."""
        if self.time_slots:
            time_slots = json.loads(self.time_slots)
        else:
            time_slots = {}

        time_slots[date] = slots
        self.time_slots = json.dumps(time_slots)

    def get_time_slots(self, date):
        """Get time slots for a specific date."""
        if self.time_slots:
            time_slots = json.loads(self.time_slots)
            return time_slots.get(date, [])
        return []
    
class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id', name='fk_game_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_name = db.Column(db.String(80), nullable=False)
    reserved_seat = db.Column(db.Integer, nullable=False)
    reserved_on = db.Column(db.DateTime, default=datetime.utcnow)
    game = db.relationship('Game', backref=db.backref('reservations', lazy=True))

    def __repr__(self):
        return f'<Reservation {self.user_name} for game {self.game_id}>'
    
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


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    court_id = db.Column(db.Integer, db.ForeignKey('court.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    players_joined = db.Column(db.Integer, default=0)
    share_link = db.Column(db.String(255), unique=True, nullable=True)

    court = db.relationship('Court', backref=db.backref('games', lazy=True))
    user = db.relationship('User', backref=db.backref('games', lazy=True))

    def __repr__(self):
        return f'<Game {self.court_id} by {self.user_id}>'
    
class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'

    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='messages')
    game = db.relationship('Game', backref='messages')