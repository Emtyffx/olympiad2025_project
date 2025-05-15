import pytest
import json
from datetime import datetime

def test_get_events(client):
    response = client.get('/api/events')
    assert response.status_code == 200
    assert isinstance(response.json, list)

def test_create_event(client):
    data = {'title': 'New Event', 'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    response = client.post('/api/events', json=data)
    assert response.status_code == 200
    assert response.json['title'] == 'New Event'

def test_create_event_invalid_data(client):
    response = client.post('/api/events', json={'title': 'Invalid'})
    assert response.status_code == 400
    assert 'error' in response.json

def test_update_event(client):
    # First, create an event
    create_data = {'title': 'To Update', 'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    create_response = client.post('/api/events', json=create_data)
    assert create_response.status_code == 200
    event_id = create_response.json['id']

    # Then, update it
    update_data = {'title': 'Updated Event', 'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    update_response = client.put(f'/api/events/{event_id}', json=update_data)
    assert update_response.status_code == 200
    assert update_response.json['title'] == 'Updated Event'

def test_update_event_not_found(client):
    update_data = {'title': 'Updated', 'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    response = client.put('/api/events/999', json=update_data)
    assert response.status_code == 404

def test_delete_event(client):
    # First, create an event
    create_data = {'title': 'To Delete', 'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    create_response = client.post('/api/events', json=create_data)
    assert create_response.status_code == 200
    event_id = create_response.json['id']

    # Then, delete it
    delete_response = client.delete(f'/api/events/{event_id}')
    assert delete_response.status_code == 204

    # Try to get it, should be not found
    get_response = client.get(f'/api/events/{event_id}')
    assert get_response.status_code == 404

def test_delete_event_not_found(client):
    response = client.delete('/api/events/999')
    assert response.status_code == 404
