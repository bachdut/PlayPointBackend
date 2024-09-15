from flask import Flask, jsonify, request, render_template, url_for, send_from_directory
from dbModel import db
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token, get_jwt
from flask_mail import Mail, Message
import logging
import random 
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
import base64
import json
from models import User, Court, Reservation, Product, GroupingProduct, Purchase, Game, ChatMessage
from flask_uploads import UploadSet, configure_uploads, IMAGES
from werkzeug.utils import secure_filename
import os

logging.basicConfig(level=logging.DEBUG)

UPLOAD_FOLDER = os.path.join('uploads', 'profilePictures')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


# Initialize SQLAlchemy and Bcrypt here without an app
bcrypt = Bcrypt()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'fUTMIHsA7L1x9EnNoW4j2tWTjD4ga0xy'
app.config['GOOGLE_CLIENT_ID'] = '136528838841-f4qtnf6psgdhr2d71953slrsh0uvoosm.apps.googleusercontent.com'
app.config['UPLOADED_PHOTOS_DEST'] = UPLOAD_FOLDER
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)
# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'

# Add the generated keys here
app.config['SECRET_KEY'] = 'lJn1o9EHY2oBpYpSmLaE2n2vy_5N67sH'
app.config['SECURITY_PASSWORD_SALT'] = 'UmyE4FW9roFPZDOGIh4pQOeYrSq9LGaz'

db.init_app(app)
bcrypt.init_app(app)
mail = Mail(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except Exception as e:
        return False
    return email

def mock_send_email(to, subject, template):
    print(f"Mock email sent to {to} with subject '{subject}'")
    print(template)

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()

    if user:
        token = generate_confirmation_token(user.email)
        reset_url = url_for('reset_with_token', token=token, _external=True)
        html = render_template('reset_password.html', reset_url=reset_url)
        mock_send_email(user.email, 'Password Reset Requested', html)  # Use the mock function
        return jsonify({'message': 'Password reset email sent'}), 200
    else:
        return jsonify({'message': 'Invalid email address'}), 400

@app.route('/reset-password/<token>', methods=['POST'])
def reset_with_token(token):
    try:
        email = confirm_token(token)
    except:
        return jsonify({'message': 'The reset link is invalid or has expired'}), 400

    data = request.get_json()
    new_password = data.get('new_password')
    user = User.query.filter_by(email=email).first()

    if user:
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        return jsonify({'message': 'Password has been reset'}), 200
    else:
        return jsonify({'message': 'Invalid user'}), 400
    
@app.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        users = User.query.all()
        user_list = []
        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                # Add any other user attributes you want to include
            }
            user_list.append(user_data)
        return jsonify(user_list), 200
    except Exception as e:
        app.logger.error(f"Error fetching users: {str(e)}")
        return jsonify({'message': 'Failed to fetch users'}), 500
    

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
    
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]  # JWT ID, a unique identifier for a JWT
    # You would normally add this JTI to a blocklist so it can't be used again
    return jsonify({"message": "Successfully logged out"}), 200

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

@app.route('/login/google', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data.get('token')

    app.logger.debug(f"Received token: {token}")

    try:
        app.logger.debug(f"Token length: {len(token)}")

        # Ensure token is Base64 encoded correctly by adding padding
        token += '=' * (-len(token) % 4)

        app.logger.debug(f"Padded token: {token}")

        try:
            base64.urlsafe_b64decode(token)
        except base64.binascii.Error as e:
            app.logger.error(f"Base64 decoding error: {e}")
            return jsonify({'message': 'Invalid token encoding'}), 400

        # Verify the token
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])

        app.logger.debug(f"Token info: {idinfo}")
        
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            return jsonify({'message': 'Invalid token issuer'}), 400

        google_id = idinfo['sub']
        email = idinfo['email']
        full_name = idinfo.get('name', email.split('@')[0])
        profile_picture = idinfo.get('picture', '')

        # Check if the user already exists
        user = User.query.filter_by(email=email).first()
        if not user:
            # Create a new user if not exists
            user = User(
                username=full_name,
                email=email,
                password='',  # Password is empty because it's a Google account
                google_id=google_id,
                full_name=full_name,
                profile_picture=profile_picture
            )
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
    except ValueError as e:
        app.logger.error(f"Token verification error: {e}")
        return jsonify({'message': 'Invalid token'}), 400

@app.route('/update-profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    try:
        data = request.form.to_dict()
        files = request.files

        logging.debug(f"Received data: {data}")
        logging.debug(f"Received files: {files}")

        if 'dateOfBirth' in data and data['dateOfBirth']:
            user.date_of_birth = datetime.strptime(data['dateOfBirth'], '%Y-%m-%d').date()
        else:
            user.date_of_birth = user.date_of_birth

        user.username = data.get('username', user.username)
        user.gender = data.get('gender', user.gender)
        user.phone = data.get('phone', user.phone)
        user.address = data.get('address', user.address)
        user.favorite_sport = data.get('favoriteSports', user.favorite_sport)
        user.professional_level = data.get('skillLevel', user.professional_level)
        user.favorite_position = data.get('sportRule', user.favorite_position)

        # Ensure healthDeclaration is a boolean
        health_declaration = data.get('healthDeclaration', user.health_declaration)
        if isinstance(health_declaration, str):
            health_declaration = health_declaration.lower() == 'true'
        user.health_declaration = health_declaration

        # Handle profile picture upload
        if 'profilePicture' in files:
            filename = secure_filename(f'{user.id}.jpg')
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            files['profilePicture'].save(filepath)
            user.profile_picture = url_for('uploaded_file', filename=filename, _external=True)

        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'}), 200
    except ValueError as e:
        logging.error(f"Error updating profile: {e}")
        return jsonify({'message': 'Invalid data format', 'error': str(e)}), 400
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500
    

# Courts routes
@app.route('/add-court', methods=['POST'])
def add_court():
    data = request.json
    time_slots = data.get('time_slots', [])

    new_court = Court(
        name=data['name'],
        location=data['location'],
        available_seats=data['available_seats'],
        price=data['price'],
        time_slots=json.dumps(time_slots),  # Store as JSON string
        image=data['image'],
        level_of_players=data.get('level_of_players', 'Beginner'),
        category=data.get('category', 'General')
    )
    db.session.add(new_court)
    db.session.commit()
    return jsonify({'message': 'Court added successfully'}), 201

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

    # Assuming you want to delete by court_id instead of name
    court_id = data.get('court_id')

    if not court_id:
        return jsonify({'message': 'Court ID is required'}), 400

    court = Court.query.get(court_id)
    if not court:
        return jsonify({'message': 'Court not found'}), 404

    try:
        db.session.delete(court)
        db.session.commit()
        return jsonify({'message': 'Court deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'An error occurred while trying to delete the court: {str(e)}'}), 500
    

@app.route('/courts', methods=['GET'])
def get_courts():
    courts = Court.query.all()
    court_list = [
        {
            'name': court.name,
            'location': court.location,
            'available_seats': court.available_seats,
            'price': court.price,
            'time_slots': court.time_slots,  # Return time slots as JSON
            'image': court.image,
            'id': court.id,
            'players_joined': court.players_joined
        }
        for court in courts
    ]
    return jsonify(court_list), 200


@app.route('/available-courts', methods=['GET'])
@jwt_required()
def get_available_courts():
    courts = Court.query.all()
    available_courts = [court for court in courts if court.players_joined == 0]
    court_list = [{'id': court.id, 'name': court.name} for court in available_courts]
    return jsonify(court_list), 200


@app.route('/reserve', methods=['POST'])
@jwt_required()
def reserve_game():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    data = request.get_json()
    game_id = data.get('game_id')
    print(f"Attempting to reserve game with ID: {game_id}")  # Log the game ID

    game = Game.query.get(game_id)
    if game:
        app.logger.debug(f'Game found: {game}')
    else:
        app.logger.debug(f'No game found with ID: {game_id}')
        return jsonify({'message': 'Game not found'}), 404

    court = game.court

    # Check if the user already has a reservation for this game
    existing_reservation = Reservation.query.filter_by(game_id=game_id, user_id=current_user_id).first()
    if existing_reservation:
        return jsonify({'message': 'You already have a reservation for this game'}), 400

    if court.available_seats > 0:
        court.available_seats -= 1
        game.players_joined += 1
        new_reservation = Reservation(
            game_id=game.id,
            user_id=current_user_id,
            user_name=current_user.username,
            reserved_seat=court.available_seats + 1,
            reserved_on=datetime.utcnow()
        )
        db.session.add(new_reservation)
        db.session.commit()
        return jsonify({'message': 'Reservation successful', 'remaining_seats': court.available_seats}), 200
    else:
        return jsonify({'message': 'No seats available'}), 400
    
@app.route('/delete-reservation', methods=['DELETE'])
@jwt_required()
def delete_reservation():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    game_id = data.get('game_id')
    
    game = Game.query.get(game_id)
    if not game:
        return jsonify({'message': 'Game not found'}), 404

    reservation = Reservation.query.filter_by(game_id=game_id, user_id=current_user_id).first()
    if reservation:
        game.court.available_seats += 1
        game.players_joined -= 1
        db.session.delete(reservation)
        db.session.commit()
        return jsonify({'message': 'Reservation deleted', 'remaining_seats': game.court.available_seats}), 200
    else:
        return jsonify({'message': 'Reservation not found'}), 404

#SHOP ROUTES

@app.route('/add-product', methods=['POST'])
def add_product():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    image_url = data.get('image_url')

    if not all([name, description, price, image_url]):
        return jsonify({'error': 'Missing data'}), 400

    new_product = Product(
        name=name,
        description=description,
        price=price,
        image_url=image_url
    )
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message': 'Product added successfully'}), 201


@app.route('/get-products', methods=['GET'])
def get_products():
    products = Product.query.all()
    products_data = [{'id': product.id, 'name': product.name, 'description': product.description, 'price': product.price, 'image_url': product.image_url} for product in products]
    return jsonify(products_data)

@app.route('/delete-product/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    
    db.session.delete(product)
    db.session.commit()
    
    return jsonify({'message': 'Product deleted successfully'})

@app.route('/add-group-product', methods=['POST'])
def add_group_product():
    data = request.json
    new_product = GroupingProduct(
        name=data['name'],
        description=data['description'],
        price=data['price'],
        image_url=data['image_url'],
        original_price=data['original_price'],
        discount_rate=data['discount_rate'],
        total_needed=data['total_needed']
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Grouping product added successfully'}), 201

@app.route('/get-group-products', methods=['GET'])
def get_group_products():
    products = GroupingProduct.query.all()
    products_data = [{'id': product.id, 'name': product.name, 'description': product.description, 'price': product.price, 'image_url': product.image_url, 'original_price': product.original_price, 'discount_rate': product.discount_rate, 'total_needed': product.total_needed, 'current_participants': product.current_participants} for product in products]
    return jsonify(products_data)

@app.route('/delete-group-product/<int:id>', methods=['DELETE'])
def delete_group_product(id):
    product = GroupingProduct.query.get(id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'}), 200

#Join Purchase API calls:
@app.route('/join-group-purchase', methods=['POST'])
def join_group_purchase():
    data = request.get_json()
    product_id = data.get('product_id')
    if not product_id:
        return jsonify({'success': False, 'message': 'Product ID is required'}), 400
    product = GroupingProduct.query.filter_by(id=product_id).first()
    if not product:
        return jsonify({'success': False, 'message': 'Product not found'}), 404
    if product.current_participants >= product.total_needed:
        return jsonify({'success': False, 'message': 'Group purchase already full'}), 400
    product.current_participants += 1
    db.session.commit()

    return jsonify({'success': True, 'product': {
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': product.price,
        'image_url': product.image_url,
        'original_price': product.original_price,
        'discount_rate': product.discount_rate,
        'total_needed': product.total_needed,
        'current_participants': product.current_participants
    }}), 200

@app.route('/buy-product', methods=['POST'])
def buy_product():
    data = request.get_json()
    product_id = data.get('product_id')
    user_id = data.get('user_id')

    if not product_id:
        return jsonify({'error': 'Product ID is required'}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    # Record the purchase
    purchase = Purchase(product_id=product_id, user_id=user_id)
    db.session.add(purchase)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Product purchased successfully'})
    
    # Record the purchase
    purchase = Purchase(product_id=product_id, user_id=user_id)
    db.session.add(purchase)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Product purchased successfully'})


@app.route('/user-details', methods=['GET'])
@jwt_required()
def user_details():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_data = {
        'username': user.username,
        'dateOfBirth': user.date_of_birth.isoformat() if user.date_of_birth else None,
        'gender': user.gender or 'Not specified',
        'healthDeclaration': user.health_declaration,
        'email': user.email,
        'phone': user.phone or '',
        'address': user.address or '',
        'favoriteSports': user.favorite_sport or '',
        'skillLevel': user.professional_level or '',
        'sportRule': user.favorite_position or '',
        'profilePicture': user.profile_picture
    }

    return jsonify(user_data), 200

@app.route('/game-details/<int:game_id>', methods=['GET'])
@jwt_required()
def get_game_details(game_id):
    current_user_id = get_jwt_identity()  # Get the current user ID from the token
    game = Game.query.get(game_id)
    if not game:
        return jsonify({'error': 'Game not found'}), 404

    court = game.court
    if not court:
        return jsonify({'error': 'Court not found'}), 404

    # Check if the current user has already joined the game
    has_reserved = Reservation.query.filter_by(game_id=game.id, user_id=current_user_id).first() is not None

    return jsonify({
        'game_id': game.id,
        'court_id': court.id,
        'name': court.name,
        'location': court.location,
        'available_seats': court.available_seats,
        'price': court.price,
        'time_slots': json.loads(court.time_slots),
        'image': court.image,
        'level_of_players': court.level_of_players,
        'category': court.category,
        'players_joined': game.players_joined,
        'start_time': game.start_time.strftime('%Y-%m-%d %H:%M'),
        'end_time': game.end_time.strftime('%Y-%m-%d %H:%M'),
        'has_reserved': has_reserved 
    }), 200



#Game Events API calls
@app.route('/court/<int:court_id>/games', methods=['GET'])
def get_court_games(court_id):
    date_str = request.args.get('date')
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format, should be YYYY-MM-DD'}), 400

    games = Game.query.filter(
        Game.court_id == court_id,
        db.func.date(Game.start_time) == date
    ).all()

    if not games:
        return jsonify({'games': []}), 200

    games_list = [
        {
            'id': game.id,
            'start_time': game.start_time.strftime('%H:%M'),
            'end_time': game.end_time.strftime('%H:%M'),
            'players_joined': game.players_joined
        } for game in games
    ]
    
    return jsonify({'games': games_list}), 200

@app.route('/games', methods=['POST'])
@jwt_required()
def create_game():
    data = request.get_json()
    court_id = data.get('court_id')
    start_time_str = data.get('start_time')
    end_time_str = data.get('end_time')

    if not court_id or not start_time_str or not end_time_str:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        start_time = datetime.strptime(start_time_str, '%Y-%m-%d %H:%M')
        end_time = datetime.strptime(end_time_str, '%Y-%m-%d %H:%M')
    except ValueError:
        return jsonify({'error': 'Invalid date format, should be YYYY-MM-DD HH:MM'}), 400

    overlapping_games = Game.query.filter(
        Game.court_id == court_id,
        Game.start_time < end_time,
        Game.end_time > start_time
    ).all()

    if overlapping_games:
        return jsonify({'error': 'Time slot overlaps with existing game(s)'}), 400

    new_game = Game(
        court_id=court_id,
        user_id=get_jwt_identity(),
        start_time=start_time,
        end_time=end_time,
        players_joined=0  # Initializing players joined to 0
    )

    db.session.add(new_game)
    db.session.commit()

    return jsonify({'message': 'Game created successfully', 'game_id': new_game.id}), 201

@app.route('/games/<int:game_id>', methods=['DELETE'])
@jwt_required()
def delete_game(game_id):
    current_user_id = get_jwt_identity()
    
    # Find the game by ID and ensure it belongs to the current user
    game = Game.query.filter_by(id=game_id, user_id=current_user_id).first()
    if not game:
        return jsonify({'message': 'Game not found or you do not have permission to delete this game'}), 404

    # Ensure players_joined is not None and proceed with the check
    if (game.players_joined or 0) > 1:
        return jsonify({'message': 'Cannot delete a game with players already joined'}), 400



    db.session.delete(game)
    db.session.commit()

    return jsonify({'message': 'Game deleted successfully'}), 200


@app.route('/court/<int:court_id>/available-times', methods=['GET'])
def get_available_time_slots(court_id):
    date_str = request.args.get('date')
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format, should be YYYY-MM-DD'}), 400

    court = Court.query.get(court_id)
    if not court:
        return jsonify({'error': 'Court not found'}), 404

    all_time_slots = json.loads(court.time_slots)  # Assuming time slots are stored as JSON

    # Fetch all games for the court on the given date
    games_on_date = Game.query.filter(
        Game.court_id == court_id,
        db.func.date(Game.start_time) == date
    ).all()

    booked_slots = []
    for game in games_on_date:
        booked_slots.append({
            'start_time': game.start_time.strftime('%H:%M'),
            'end_time': game.end_time.strftime('%H:%M')
        })

    # Filter out the booked slots from all time slots
    available_slots = []
    for slot in all_time_slots:
        slot_start_time, slot_end_time = slot.split('-')
        if not any(
            booked['start_time'] <= slot_start_time < booked['end_time'] or
            booked['start_time'] < slot_end_time <= booked['end_time']
            for booked in booked_slots
        ):
            available_slots.append(slot)

    return jsonify({'available_slots': available_slots}), 200

@app.route('/my-hosted-games', methods=['GET'])
@jwt_required()
def get_my_hosted_games():
    user_id = get_jwt_identity()
    hosted_games = Game.query.filter_by(user_id=user_id).all()

    games_list = [
        {
            'id': game.id,
            'court_name': game.court.name,
            'start_time': game.start_time.strftime('%Y-%m-%d %H:%M'),
            'end_time': game.end_time.strftime('%Y-%m-%d %H:%M')
        }
        for game in hosted_games
    ]

    return jsonify(games_list), 200

@app.route('/open-games', methods=['GET'])
def get_open_games():
    location = request.args.get('location')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    max_price = request.args.get('price')
    level_of_players = request.args.get('level_of_players')  # Updated field

    # Convert date strings to datetime objects if provided
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None

    # Query to get open games
    games_query = Game.query.join(Court)

    if location:
        games_query = games_query.filter(Court.location.ilike(f'%{location}%'))
    if start_date:
        games_query = games_query.filter(Game.start_time >= start_date)
    if end_date:
        games_query = games_query.filter(Game.end_time <= end_date)
    if max_price:
        games_query = games_query.filter(Court.price <= float(max_price))
    if level_of_players:  # Updated filter
        games_query = games_query.filter(Court.level_of_players.ilike(f'%{level_of_players}%'))

    open_games = games_query.all()

    games_list = [
        {
        'id': game.id,
        'court_id': game.court_id, 
        'court_name': game.court.name,
        'location': game.court.location,
        'start_time': game.start_time.strftime('%Y-%m-%d %H:%M'),
        'end_time': game.end_time.strftime('%Y-%m-%d %H:%M'),
        'price': game.court.price,
        'level_of_players': game.court.level_of_players,
        'players_joined': game.players_joined,
        }
        for game in open_games
    ]

    return jsonify({'games': games_list}), 200


@app.route('/shuffle-game/<int:game_id>', methods=['POST'])
@jwt_required()
def shuffle_game(game_id):
    game = Game.query.get(game_id)
    if not game:
        return jsonify({'error': 'Game not found'}), 404

    shuffle_type = request.json.get('shuffle_type')

    # Fetch players who have joined this game
    reservations = Reservation.query.filter_by(game_id=game_id).all()
    if not reservations:
        return jsonify({'error': 'No players to shuffle'}), 400

    player_ids = [res.user_id for res in reservations]
    players = User.query.filter(User.id.in_(player_ids)).all()

    team1 = []
    team2 = []

    if shuffle_type == 'random':
        # Random shuffle
        random.shuffle(players)
        team1 = players[::2]
        team2 = players[1::2]
    elif shuffle_type == 'level' or shuffle_type == 'fair':
        # Handle None values for professional_level by setting a default value
        for player in players:
            if player.professional_level is None:
                player.professional_level = 'No Level'  # Or any default value like 'Mid Level'

        # Sort players by their level and then split into two teams
        players.sort(key=lambda x: x.professional_level, reverse=True)
        
        for i, player in enumerate(players):
            if len(team1) > len(team2):
                team2.append(player)
            else:
                team1.append(player)
    else:
        return jsonify({'error': 'Invalid shuffle type'}), 400

    # Return the shuffled teams
    return jsonify({
        'team1': [player.username for player in team1],
        'team2': [player.username for player in team2]
    }), 200

#Chat API functions

@app.route('/game/<int:game_id>/chat', methods=['POST'])
@jwt_required()
def post_chat_message(game_id):
    current_user = get_jwt_identity()  # Get the currently authenticated user
    data = request.get_json()

    message_text = data.get('message')
    if not message_text:
        return jsonify({'error': 'Message cannot be empty'}), 400

    game = Game.query.get(game_id)
    if not game:
        return jsonify({'error': 'Game not found'}), 404

    # Ensure the user has joined the game
    reservation = Reservation.query.filter_by(user_id=current_user, game_id=game_id).first()
    if not reservation:
        return jsonify({'error': 'You must be part of the game to send messages'}), 403

    # Create a new chat message
    new_message = ChatMessage(
        game_id=game_id,
        user_id=current_user,
        message=message_text
    )
    db.session.add(new_message)
    db.session.commit()

    return jsonify({
        'username': new_message.user.username,
        'sender_id': new_message.user.id,
        'content': new_message.message,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'message_id': new_message.id
    }), 201



@app.route('/game/<int:game_id>/chat', methods=['GET'])
@jwt_required()
def get_chat_messages(game_id):
    current_user_id = get_jwt_identity()

    # Check if the user has joined the game
    reservation = Reservation.query.filter_by(game_id=game_id, user_id=current_user_id).first()
    if not reservation:
        return jsonify({'error': 'User has not joined this game'}), 403

    messages = ChatMessage.query.filter_by(game_id=game_id).order_by(ChatMessage.timestamp.asc()).all()

    chat_history = [
        {
            'username': message.user.username,
            'sender_id': message.user.id,
            'content': message.message,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'message_id': message.id
        }
        for message in messages
    ]

    return jsonify(chat_history), 200


@app.route('/game/<int:game_id>/delete-message/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(game_id, message_id):
    user_id = get_jwt_identity()
    
    # Check if the message exists
    message = ChatMessage.query.filter_by(id=message_id, game_id=game_id).first()

    if not message:
        return jsonify({'error': 'Message not found'}), 404

    # Only the author of the message or the host can delete the message
    if message.user.id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    # Perform the deletion
    db.session.delete(message)
    db.session.commit()

    return jsonify({'message': 'Message deleted successfully'}), 200

#Profile pic 
@app.route('/uploads/profilePictures/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


from models import User, Court, Reservation  # Ensure this import is at the end

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create all tables
    app.run(debug=True, port=8888)