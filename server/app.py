import os
import re
import json
import phonenumbers
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail  
from datetime import datetime
from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, session, jsonify, current_app, redirect, url_for, render_template, send_from_directory, abort
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager, login_required, logout_user, current_user
# from flask_mail import Mail, Message
from flask_migrate import Migrate
from models import db, Retreat, Inquiry, Participant, Booking, User

load_dotenv()
# price = os.getenv('PRICE')
# if price is None or price == '':
#     raise ValueError('You must set a Price ID in the .env file. Please see README.md for instructions')

# # Set Stripe API key
# stripe.api_version = '2020-08-27'
# stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
# webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

# static_dir = str(os.path.abspath(os.path.join(
#      __file__, "..", os.getenv("STATIC_DIR"))))


# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///development.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] ='Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'

# Initialize Flask-Mail
# app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False
# app.config['MAIL_USERNAME'] = 'info@thetaylorcut.com' 
# app.config['MAIL_PASSWORD'] = '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'

# Initialize Flask extensions
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
mail = Mail(app)
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader function for Flask LoginManager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper function to handle common error response
def error_response(message, status_code):
    response = {'error': message}
    return jsonify(response), status_code

@app.route('/')
def home():
    return 'Welcome to the TaylorCut fitness website!'

# #! Stripe routes
# @app.route('/config', methods=['GET'])
# def get_publishable_key():
#     price = stripe.Price.retrieve(os.getenv('PRICE'))
#     return jsonify({
#       'publicKey': os.getenv('pk_live_51NB5DWDTvALTJdoO0N2BN1Q3vn18fadpN4aaBg3ry9sWbl8esiEQ485yqe8yzY0lyiWLYjpd38HF3WlycNHmJKF200QZldhgE7'),
#       'unitAmount': price['unit_amount'],
#       'currency': price['currency']
#     })

# # Fetch the Checkout Session to display the JSON result on the success page
# @app.route('/checkout-session', methods=['GET'])
# def get_checkout_session():
#     id = request.args.get('sessionId')
#     checkout_session = stripe.checkout.Session.retrieve(id)
#     return jsonify(checkout_session)

# @app.route('/create-checkout-session', methods=['POST'])
# def create_checkout_session():
#     quantity = request.form.get('quantity', 1)
#     domain_url = os.getenv('DOMAIN')

#     try:
#         checkout_session = stripe.checkout.Session.create(
#             success_url=domain_url + '/success.html?session_id={CHECKOUT_SESSION_ID}',
#             cancel_url=domain_url + '/canceled.html',
#             mode='payment',
#             automatic_tax={'enabled': True},
#             line_items=[{
#                 'price': os.getenv('PRICE'),
#                 'quantity': quantity,
#             }]
#         )
#         return redirect(checkout_session.url, code=303)
#     except Exception as e:
#         return jsonify(error=str(e)), 403


# @app.route('/webhook', methods=['POST'])
# def webhook_received():
#     # You can use webhooks to receive information about asynchronous payment events.
#     # For more about our webhook events check out https://stripe.com/docs/webhooks.
#     webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
#     request_data = json.loads(request.data)

#     if webhook_secret:
#         # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
#         signature = request.headers.get('stripe-signature')
#         try:
#             event = stripe.Webhook.construct_event(
#                 payload=request.data, sig_header=signature, secret=webhook_secret)
#             data = event['data']
#         except Exception as e:
#             return e
#         # Get the type of webhook event sent - used to check the status of PaymentIntents.
#         event_type = event['type']
#     else:
#         data = request_data['data']
#         event_type = request_data['type']
#     data_object = data['object']

#     print('event ' + event_type)

#     if event_type == 'checkout.session.completed':
#         print('🔔 Payment succeeded!')

#     return jsonify({'status': 'success'})

#! User routes
@app.route("/check_session")
def check_session():
  if "user_id" in session:
    user = User.query.get(session["user_id"])
    return jsonify({"user": user.to_dict()}), 200
  else:
    return jsonify({"error": "User is not logged in"}), 401

@app.route("/")
def index():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        return jsonify({"status": "User is already logged in", "user": user.to_dict()}), 200
    else:
        return jsonify({"status": "User is not logged in"}), 401


@app.route("/users", methods=["GET", "POST"])
def users():
    if request.method == "GET":
        users = User.query.all()  # Retrieve all User objects from the database
        users_list = [user.to_dict() for user in users]  # Convert each User object to a dictionary
        return jsonify(users_list), 200

    else:
        # Get the user input
        user_data = request.get_json()
        first_name = user_data["first_name"]
        last_name = user_data["last_name"]
        email = user_data["email"]
        password = user_data["password"]

        # Validate the user input
        if not validate_email(email):
          return jsonify({"error": "Invalid email address"}), 400
        if len(password) < 8:
          return jsonify({"error": "Password must be at least 8 characters long"}), 400
        if not re.search(r'[A-Z]', password):
          return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not re.search(r'[^a-zA-Z0-9]', password):
          return jsonify({"error": "Password must contain at least one special character"}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create the user
        user = User(first_name=first_name, last_name=last_name, email=email, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()

        # Add the user to the session
        session["user_id"] = user.id
        session["user_token"] = user.generate_token()

        return jsonify({"status": "User created successfully", "user": user.to_dict()}), 201

def validate_email(email):
  """Validates an email address."""
  regex = r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+$'
  return re.match(regex, email)

#! Login/Logout routes

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

    
@app.route('/logout', methods=['DELETE'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 204

#! Retreat routes

@app.route('/retreat')
def get_retreats():
    retreats = Retreat.query.all()
    serialized_retreats = [retreat.serialize() for retreat in retreats]
    return jsonify(serialized_retreats)

@app.route('/retreat/<int:id>')
def get_retreat(id):
    retreat = Retreat.query.get(id)
    return jsonify(retreat.serialize())

@app.route('/retreat', methods=['POST'])
def create_retreat():
    data = request.json
    retreat = Retreat(
        name=data['name'],
        location=data['location'],
        description=data['description'],
        start_date=datetime.strptime(data['start_date'], "%Y-%m-%d"),
        end_date=datetime.strptime(data['end_date'], "%Y-%m-%d"),
        price=data['price']
    )
    db.session.add(retreat)
    db.session.commit()
    return jsonify(retreat.serialize())

@app.delete('/retreat/<int:id>')
def delete_retreat(id):
    retreat = Retreat.query.get(id)
    db.session.delete(retreat)
    db.session.commit()
    return jsonify(retreat.serialize())

#! Inquiry routes

@app.route('/submit_inquiry', methods=['POST'])
def submit_inquiry():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    phone_number = data.get('phone_number')
    message = data.get('message')

    if name and email and phone_number and message:
        try:
            parsed_number = phonenumbers.parse(phone_number, "US")  # Replace "US" with the appropriate country code
            if not phonenumbers.is_valid_number(parsed_number):
                raise ValueError("Invalid phone number.")
            
            formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        except phonenumbers.phonenumberutil.NumberParseException:
            raise ValueError("Invalid phone number.")

        inquiry = Inquiry(name=name, email=email, phone_number=formatted_number, message=message)
        db.session.add(inquiry)
        db.session.commit()
        send_confirmation_email(email)
        return jsonify({'message': 'Inquiry submitted successfully!'})

    return jsonify({'error': 'Invalid data provided.'}), 400


def send_confirmation_email(email):
    message = Mail(
        from_email = 'info@thetaylorcut.com',
        to_emails = email,
        subject = 'Inquiry Confirmation',
        html_content = "<strong>Thank you for your inquiry! We're happy to receive your inquiry and will be in touch with you within 24-48 hours. Keep being awesome!</strong>")
    
    sg=SendGridAPIClient('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')
    response = sg.send(message)
    print(response.status_code)
    print(response.body)
    print(response.headers)
    # except Exception as e:
    #     print(e)
    # Create the email message
    # msg = Message("Inquiry Confirmation",
    #             sender=app.config['MAIL_USERNAME'],
    #             recipients=[email])

    # # Customize the email content
    # msg.body = "Thank you for your inquiry! We're happy to receive your inquiry and will be in touch with you within 24-48 hours. Keep being awesome!"

    # # Send the email
    # mail.send(msg)

@app.route('/leads')
def get_leads():
    leads = Inquiry.query.filter_by(booked=False).all()
    serialized_leads = [lead.serialize() for lead in leads]
    return jsonify(serialized_leads)

@app.route('/lead/<int:id>')
def get_lead(id):
    lead = Inquiry.query.get(id)
    return jsonify(lead.serialize())

#! Participant routes
# Get all participants
@app.route('/participant', methods=['POST'])
def create_participant():
    data = request.json

    # Perform gender validation
    valid_genders = ['Male', 'Female', 'Non-Binary', 'Prefer not to say']
    if data['gender'] not in valid_genders:
        return jsonify({'error': 'Invalid gender'}), 400

    # Check if the user is logged in
    if current_user.is_authenticated:
        user_id = current_user.id
    else:
        user_id = None

    participant = Participant(
        first_name=data['first_name'],
        last_name=data['last_name'],
        email=data['email'],
        phone_number=data['phone_number'],
        date_of_birth=datetime.strptime(data['date_of_birth'], "%Y-%m-%d"),
        gender=data['gender'],
        country_of_residence=data['country_of_residence'],
        city=data['city'],
        state=data['state'],
        zip_code=data['zip_code'],
        t_shirt_size=data['t_shirt_size'],
        user_id=user_id  # Use the current user's id
    )
    db.session.add(participant)
    db.session.commit()

    return jsonify({'message': 'Participant created successfully'}), 200

# Get a specific participant
@app.route('/participant/<int:id>', methods=['GET'])
def get_participant(id):
    participant = Participant.query.get(id)
    if participant is None:
        return jsonify({'error': 'Participant not found'}), 404
    return jsonify(participant.serialize())

# Update a participant
@app.route('/participant/<int:id>', methods=['PATCH'])
def update_participant(id):
    data = request.json
    participant = Participant.query.get(id)
    if participant is None:
        return jsonify({'error': 'Participant not found'}), 404
    for key, value in data.items():
        setattr(participant, key, value)
    db.session.commit()
    return jsonify(participant.serialize())

# Delete a participant
@app.route('/participant/<int:id>', methods=['DELETE'])
def delete_participant(id):
    participant = Participant.query.get(id)
    if participant is None:
        return jsonify({'error': 'Participant not found'}), 404
    db.session.delete(participant)
    db.session.commit()
    return jsonify({'success': 'Participant deleted'})

#! Booking routes
@app.route('/booking')
def get_bookings():
  bookings = Booking.query.all()
  serialized_bookings = [booking.serialize() for booking in bookings]
  return jsonify(serialized_bookings)

@app.route('/booking/<int:id>')
def get_booking(id):
  booking = Booking.query.get(id)
  return jsonify(booking.serialize())

@app.route('/booking', methods=['POST'])
def create_booking():
    data = request.json
    booking = Booking(
        participant_id=data['participant_id'],
        retreat_id=data['retreat_id'],
        stripe_payment_id=data['stripe_payment_id']
    )
    db.session.add(booking)
    db.session.commit()
    return jsonify(booking.serialize())

@app.delete('/booking/<int:id>')
def delete_booking(id):
  booking = Booking.query.get(id)
  db.session.delete(booking)
  db.session.commit()
  return jsonify(booking.serialize())


if __name__ == '__main__':
    # Run the flask app
    app.run(debug=True, port=3001)
