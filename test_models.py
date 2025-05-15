import pytest
from app import User, Event, File, Teacher, Admin

def test_user_creation(client):
    with client.application.app_context():
        user = User(login='test', name='Test', surname='User', tel='123', clas=1, password='password', role='student')
        assert user.login == 'test'
        assert user.role == 'student'

def test_event_creation(client):
    with client.application.app_context():
        from datetime import datetime
        event = Event(title='Test Event', date=datetime.now())
        assert event.title == 'Test Event'

def test_file_creation(client):
    with client.application.app_context():
        file = File(file_name='test.txt')
        assert file.file_name == 'test.txt'

def test_teacher_creation(client):
    with client.application.app_context():
        teacher = Teacher(login='teacher1', first_name='John', last_name='Doe', class_name='Science', password='password')
        assert teacher.login == 'teacher1'
        assert teacher.class_name == 'Science'

def test_admin_creation(client):
    with client.application.app_context():
        admin = Admin(login='admin1', first_name='Jane', last_name='Doe', password='password')
        assert admin.login == 'admin1'
