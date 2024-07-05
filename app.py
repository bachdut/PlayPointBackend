from flask import Flask, jsonify, request, render_template, url_for, send_from_directory
from dbModel import db
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from flask_mail import Mail, Message
import logging
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
import base64
from models import User, Court, Reservation, Product, GroupingProduct, Purchase
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


@app.route('/uploads/profilePictures/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


from models import User, Court, Reservation  # Ensure this import is at the end

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create all tables
    app.run(debug=True, port=8888)