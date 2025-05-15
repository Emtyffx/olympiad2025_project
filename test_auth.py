import pytest
from app import User

def test_register_user(client):
    response = client.post(
        '/register',
        data={
            'login': 'newuser',
            'name': 'New',
            'surname': 'User',
            'tel': '456',
            'clas': 2,
            'password': 'newpassword',
            'role': 'student'
        },
        follow_redirects=True
    )
    assert response.status_code == 200
    assert 'Реєстрація успішна!'.encode("utf-8") in response.data
    with client.application.app_context():
        assert User.query.filter_by(login='newuser').first() is not None

def test_register_existing_user(client):
    # Assuming a user exists (you might need to create one in a fixture)
    client.post(
        '/register',
        data={
            'login': 'testuser',  # Existing user from fixture
            'name': 'Test',
            'surname': 'User',
            'tel': '123',
            'clas': 1,
            'password': 'password',
            'role': 'student'
        },
        follow_redirects=True
    )
    response = client.post(
        '/register',
        data={
            'login': 'testuser',
            'name': 'Another',
            'surname': 'User',
            'tel': '789',
            'clas': 3,
            'password': 'anotherpassword',
            'role': 'parent'
        },
        follow_redirects=True
    )
    assert response.status_code == 200
    assert 'Такий користувач вже існує'.encode("utf-8") in response.data

def test_login_user(client, user):
    response = client.post(
        '/login',
        data={'login': 'testuser', 'password': 'password'},
        follow_redirects=True
    )
    assert response.status_code == 200
    assert 'Ваш логин: Test'.encode("utf-8") in response.data  # Adjust based on your home page content

def test_login_invalid_credentials(client):
    response = client.post(
        '/login',
        data={'login': 'wronguser', 'password': 'wrongpassword'},
        follow_redirects=True
    )
    assert response.status_code == 200
    assert 'Невірні дані'.encode("utf-8") in response.data

def test_logout_user(client, user):
    with client.session_transaction() as session:
        session['user_id'] = user.id  # Simulate login
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert 'Вхід'.encode("utf-8") in response.data  # Adjust based on your login page content
    with client.session_transaction() as session:
        assert 'user_id' not in session
