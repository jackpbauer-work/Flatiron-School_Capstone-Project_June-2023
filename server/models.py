from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint
from sqlalchemy.ext.associationproxy import association_proxy
from datetime import datetime, timedelta
from sqlalchemy.orm import validates
from flask_bcrypt import Bcrypt
import re
from email_validator import validate_email, EmailNotValidError
from flask_login import UserMixin
import phonenumbers
import jwt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///development.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)



class SerializeMixin:
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class Inquiry(db.Model):
    __tablename__ = 'inquiries'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint('LENGTH(message) <= 1000', name='check_message_length'),
    )


    @validates('email')
    def validate_email(self, key, email):
        if not email:
            raise ValueError("Email is required.")
        try:
            v = validate_email(email)
            email = v.email
        except EmailNotValidError:
            raise ValueError("Invalid email address.")
        return email

    @validates('phone_number')
    def validate_phone_number(self, key, phone_number):
        if not phone_number:
            raise ValueError("Phone number is required.")
        try:
            parsed_number = phonenumbers.parse(phone_number, None)
            if not phonenumbers.is_valid_number(parsed_number):
                raise ValueError("Invalid phone number.")
        except phonenumbers.phonenumberutil.NumberParseException:
            raise ValueError("Invalid phone number.")
        return phone_number

    def validate(self):
        errors = []

        if not self.name:
            errors.append("Name is required.")

        if not self.email:
            errors.append("Email is required.")

        if not self.phone_number:
            errors.append("Phone number is required.")

        if not self.message:
            errors.append("Message is required.")

        return errors
    
    def __repr__(self):
        return f'<Inquiry>'


class User(db.Model, UserMixin, SerializeMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    participant = db.relationship("Participant", uselist=False, back_populates="user")

    @validates('email')
    def validate_email(self, key, value):
        if not validate_email(value):
            raise ValueError('Invalid email address')
        return value

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @staticmethod
    def validate_password(password):
        if len(password) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', password):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[^a-zA-Z0-9]', password):
            raise ValueError('Password must contain at least one special character')

    @password.setter
    def password(self, password):
        self.validate_password(password)
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def generate_token(self):
        payload = {
        'user_id': self.id,
        'exp': datetime.utcnow() + timedelta(days=1)
    }
        token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        return token


    def __repr__(self):
        return f'<User {self.email} {self.password}>'


from datetime import datetime

import phonenumbers

class Participant(db.Model):
    __tablename__ = 'participants'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(12), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(100), nullable=False)
    country_of_residence = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(100), nullable=False)
    t_shirt_size = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='participant')
    bookings = db.relationship('Booking', back_populates='participant', cascade="all, delete-orphan")
    retreats = association_proxy('bookings', 'retreat')

    def __init__(self, first_name, last_name, email, phone_number, date_of_birth, gender, country_of_residence, city, state, zip_code, t_shirt_size, user_id):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone_number = phone_number
        self.date_of_birth = date_of_birth
        self.gender = gender
        self.country_of_residence = country_of_residence
        self.city = city
        self.state = state
        self.zip_code = zip_code
        self.t_shirt_size = t_shirt_size
        self.user_id = user_id

    def __repr__(self):
        return f'Participant({self.first_name}, {self.last_name})'

    def validate_date_of_birth(date_of_birth):
        try:
            date_of_birth = datetime.strptime(date_of_birth, "%Y-%m-%d")
        except ValueError:
            return False
        return True

    @validates('email')
    def validate_email(self, key, value):
        if not validate_email(value):
            raise ValueError('Invalid email address')
        return value

    @validates('phone_number')
    def validate_phone_number(self, key, phone_number):
        if not phonenumbers.is_valid_number(phonenumbers.parse(phone_number, "US")):
            raise ValueError('Invalid phone number')
        return phone_number
    
    
    @validates('gender')
    def validate_gender(self, key, gender):
        valid_genders = ['Male', 'Female', 'Non-Binary', 'Prefer not to say']
        if gender not in valid_genders:
            raise ValueError('Invalid gender')
        return gender


    def __repr__(self):
        return f'<Participant {self.first_name} {self.last_name} {self.date}>'



class Booking(db.Model, SerializeMixin):
    __tablename__ = 'bookings'

    id = db.Column(db.Integer, primary_key=True)
    participant_id = db.Column(db.Integer, db.ForeignKey('participants.id'), nullable=False)
    retreat_id = db.Column(db.Integer, db.ForeignKey('retreats.id'), nullable=False)
    stripe_payment_id = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    participant = db.relationship('Participant', back_populates='bookings')
    retreat = db.relationship('Retreat', back_populates='bookings')

    def __repr__(self):
        return f'<Booking {self.id}>'


class Retreat(db.Model, SerializeMixin):
    __tablename__ = 'retreats'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(1000), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    price = db.Column(db.Float, nullable=False)

    bookings = db.relationship('Booking', back_populates='retreat', lazy=True)
    participants = association_proxy('bookings', 'participant')

    @property
    def duration(self):
        return self.end_date - self.start_date

    def __repr__(self):
        return f'<Retreat {self.name}>'


if __name__ == '__main__':
    app.run(debug=True)
