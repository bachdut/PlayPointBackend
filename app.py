from flask import Flask, jsonify, request
from dbModel import db
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token
import logging
from datetime import datetime
from google.oauth2 import id_token
from google.auth.transport import requests

logging.basicConfig(level=logging.DEBUG)

# Initialize SQLAlchemy and Bcrypt here without an app
bcrypt = Bcrypt()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'fUTMIHsA7L1x9EnNoW4j2tWTjD4ga0xy'
db.init_app(app)
bcrypt.init_app(app)

jwt = JWTManager(app)
migrate = Migrate(app, db)

# Google OAuth 2.0 client ID
GOOGLE_CLIENT_ID = 'your-google-client-id'

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already in use'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {'id': user.id, 'username': user.username}
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/login/google', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data.get('token')
    
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            return jsonify({'message': 'Invalid token issuer'}), 400

        email = idinfo['email']
        username = idinfo.get('name', email.split('@')[0])

        # Check if the user already exists
        user = User.query.filter_by(email=email).first()
        if not user:
            # Create a new user if not exists
            user = User(username=username, email=email, password='')
            db.session.add(user)
            db.session.commit()

        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {'id': user.id, 'username': user.username}
        }), 200
    except ValueError:
        # Invalid token
        return jsonify({'message': 'Invalid token'}), 400

@app.route('/update-profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    user.full_name = data.get('full_name', user.full_name)
    user.gender = data.get('gender', user.gender)
    date_of_birth_str = data.get('date_of_birth', None)
    if date_of_birth_str:
        user.date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()
    user.favorite_sport = data.get('favorite_sport', user.favorite_sport)
    user.professional_level = data.get('professional_level', user.professional_level)
    user.favorite_position = data.get('favorite_position', user.favorite_position)
    user.location = data.get('location', user.location)
    user.profile_picture = data.get('profile_picture', user.profile_picture)

    db.session.commit()
    return jsonify({'message': 'Profile updated successfully'}), 200


@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({'message': 'Logout successful'}), 200

# Courts routes
@app.route('/add-court', methods=['POST'])
def add_court():
    data = request.get_json()
    existing_court = Court.query.filter_by(name=data['name']).first()
    if existing_court:
        return jsonify({'message': 'Court with this name already exists!'}), 400
    new_court = Court(
        name=data['name'],
        location=data['location'],
        available_seats=data['available_seats']
    )
    db.session.add(new_court)
    db.session.commit()
    return jsonify({'message': 'Court added successfully!'}), 201

@app.route('/update-court', methods=['PUT'])
def update_court():
    data = request.get_json()
    current_name = data['current_name']  # Get the current court name from the request body
    court = Court.query.filter_by(name=current_name).first()  # Find the court by its current name
    if not court:
        return jsonify({'message': 'Court not found'}), 404

    # Update court details if provided
    court.name = data.get('new_name', court.name)  # Update the court name if a new name is provided
    court.location = data.get('new_location', court.location)  # Update the court location if a new location is provided
    court.available_seats = data.get('new_available_seats', court.available_seats)  # Update the available seats if a new number is provided
    
    db.session.commit()  # Commit the changes to the database
    return jsonify({'message': 'Court updated successfully!'}), 200  # Return a success message

@app.route('/delete-court', methods=['DELETE'])
def delete_court():
    data = request.get_json()
    court_name = data['name']  # Get the court name from the request body
    court = Court.query.filter_by(name=court_name).first()  # Find the court by its name
    if not court:
        return jsonify({'message': 'Court not found'}), 404

    # Check if there are any reservations for the court
    reservations = Reservation.query.filter_by(court_id=court.id).all()
    if reservations:
        return jsonify({'message': 'Court cannot be deleted because it is reserved'}), 400

    try:
        db.session.delete(court)
        db.session.commit()
        return jsonify({'message': 'Court deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'An error occurred while trying to delete the court: ' + str(e)}), 500

@app.route('/courts')
def get_courts():
    courts = Court.query.all()
    court_data = [{'id': court.id, 'name': court.name, 'location': court.location, 'available_seats': court.available_seats} for court in courts]
    return jsonify(court_data)

@app.route('/reserve', methods=['POST'])
@jwt_required()
def reserve_court():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    data = request.get_json()
    court_name = data.get('court_name')
    court = Court.query.filter_by(name=court_name).first()
    if court:
        # Check if the user already has a reservation for this court
        existing_reservation = Reservation.query.filter_by(court_id=court.id, user_id=current_user_id).first()
        if existing_reservation:
            return jsonify({'message': 'You already have a reservation for this court'}), 400

        if court.available_seats > 0:
            court.available_seats -= 1
            new_reservation = Reservation(
                court_id=court.id, 
                user_id=current_user_id,
                user_name=current_user.username,
                court_name=court.name,
                reserved_seat=court.available_seats + 1,
                reserved_on=datetime.utcnow() 
            )
            db.session.add(new_reservation)
            db.session.commit()
            return jsonify({'message': 'Reservation successful', 'remaining_seats': court.available_seats}), 200
        else:
            return jsonify({'message': 'No seats available'}), 400
    else:
        return jsonify({'message': 'Court not found'}), 404

@app.route('/delete-reservation', methods=['DELETE'])
@jwt_required()
def delete_reservation():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    court_name = data.get('court_name')
    court = Court.query.filter_by(name=court_name).first()
    if court:
        reservation = Reservation.query.filter_by(court_id=court.id, user_id=current_user_id).first()
        if reservation:
            court.available_seats += 1
            db.session.delete(reservation)
            db.session.commit()
            return jsonify({'message': 'Reservation deleted', 'remaining_seats': court.available_seats}), 200
        else:
            return jsonify({'message': 'Reservation not found'}), 404
    else:
        return jsonify({'message': 'Court not found'}), 404

from models import User, Court, Reservation  # Moved this line to the end

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create all tables
    app.run(debug=True, port=8888)