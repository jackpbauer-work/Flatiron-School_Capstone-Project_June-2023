from faker import Faker
from datetime import datetime
from models import db, Retreat, Inquiry, Participant, Booking, User
from flask_bcrypt import Bcrypt
from flask import Flask
from sqlalchemy.orm import validates
from validate_email import validate_email
from flask_login import UserMixin
import phonenumbers

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///development.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

bcrypt = Bcrypt(app)
fake = Faker()

def create_fake_data():
    with app.app_context():
        db.create_all()

        # Create example users
        user1 = User(
            first_name='John',
            last_name='Doe',
            email='john.doe@example.com',
            password=bcrypt.generate_password_hash('password').decode('utf-8'),
            created_at=datetime.utcnow()
        )

        db.session.add(user1)
        db.session.commit()

        # Create example retreats
        retreat1 = Retreat(
            name='5 Day Guatemala Retreat',
            location='Guatemala',
            description='Join us for an amazing 5-day retreat in beautiful Guatemala.',
            start_date=datetime(2023, 10, 20),
            end_date=datetime(2023, 10, 25),
            price=2500.00
        )

        db.session.add(retreat1)
        db.session.commit()

        # Create example participants
        for _ in range(10):
            phone_number = None
            while phone_number is None or not phonenumbers.is_valid_number(phonenumbers.parse(phone_number, "US")):
                phone_number = fake.phone_number()

            date_of_birth = fake.date_of_birth(minimum_age=18, maximum_age=65)

            participant = Participant(
                first_name=fake.first_name(),
                last_name=fake.last_name(),
                email=fake.email(),
                phone_number=phone_number,
                date_of_birth=date_of_birth,
                gender=fake.random_element(['Male', 'Female', 'Non-binary', 'Prefer not to say']),
                country_of_residence=fake.country(),
                city=fake.city(),
                state=fake.state(),
                zip_code=fake.zipcode(),
                t_shirt_size=fake.random_element(['S', 'M', 'L', 'XL']),
                user_id=user1.id
            )
            db.session.add(participant)

        db.session.commit()

        # Create example bookings
        retreats = Retreat.query.all()
        participants = Participant.query.all()

        for _ in range(10):
            booking = Booking(
                participant=fake.random_element(participants),
                retreat=retreat1,
                stripe_payment_id=fake.uuid4(),
                created_at=fake.date_time_between(start_date='-1y', end_date='now')
            )
            db.session.add(booking)

        db.session.commit()

        # Create example inquiries
        for _ in range(10):
            inquiry = Inquiry(
                name=fake.name(),
                email=fake.email(),
                phone_number=fake.phone_number(),
                message=fake.sentence(),
                created_at=fake.date_time_between(start_date='-1y', end_date='now')
            )
            db.session.add(inquiry)

        db.session.commit()


if __name__ == '__main__':
    create_fake_data()
