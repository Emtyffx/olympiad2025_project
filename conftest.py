import pytest
from app import app, db  # Assuming your Flask app is in 'your_app.py'

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.session.remove()
            db.drop_all()

@pytest.fixture
def runner():
    return app.test_cli_runner()

@pytest.fixture
def user(client):
    with app.app_context():
        from app import User
        new_user = User(login='testuser', name='Test', surname='User', password='password', role='student')
        db.session.add(new_user)
        db.session.commit()
        return new_user

@pytest.fixture
def teacher(client):
    with app.app_context():
        from app import Teacher
        new_teacher = Teacher(login='testteacher', first_name='Test', last_name='Teacher', class_name='Math', password='password')
        db.session.add(new_teacher)
        db.session.commit()
        return new_teacher

@pytest.fixture
def admin_user(client):
    with app.app_context():
        from app import Admin
        new_admin = Admin(login='testadmin', first_name='Test', last_name='Admin', password='password')
        db.session.add(new_admin)
        db.session.commit()
        return new_admin
