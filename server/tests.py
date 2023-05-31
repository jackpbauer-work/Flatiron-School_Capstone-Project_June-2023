import unittest

from app import get_retreats, get_participant, get_schedule, get_booking, get_testimonial


class TestGetRetreats(unittest.TestCase):

    def test_get_retreats_returns_a_list_of_retreats(self):
        retreats = get_retreats()
        self.assertIsInstance(retreats, list)
        self.assertTrue(retreats)


class TestGetParticipant(unittest.TestCase):

    def test_get_participant_returns_a_participant(self):
        participant = get_participant(1)
        self.assertIsInstance(participant, Participant)


class TestGetSchedule(unittest.TestCase):

    def test_get_schedule_returns_a_schedule(self):
        schedule = get_schedule(1)
        self.assertIsInstance(schedule, Schedule)


class TestGetBooking(unittest.TestCase):

    def test_get_booking_returns_a_booking(self):
        booking = get_booking(1)
        self.assertIsInstance(booking, Booking)


class TestGetTestimonial(unittest.TestCase):

    def test_get_testimonial_returns_a_testimonial(self):
        testimonial = get_testimonial(1)
        self.assertIsInstance(testimonial, Testimonial)


if __name__ == '__main__':
    unittest.main()
