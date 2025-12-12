from flask import Flask, render_template, redirect, url_for, session, request
import os
from dotenv import load_dotenv
import requests
from datetime import timedelta

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Session security configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # 30 days session
app.config['SESSION_PERMANENT'] = True

# Helper function to get client IP
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

@app.route('/')
def root():
    return redirect(url_for('home'))

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        if 'user_token' in session:
            return redirect(url_for('panel'))
        response = app.make_response(render_template('index.html'))
        # Prevent caching of login page
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    # POST request handling
    user_token = request.form.get('user_token', '').strip()

    if not user_token:
        return render_template('index.html', error='User token is required'), 400

    # Verify user token by fetching current user
    headers = {'Authorization': user_token}
    resp = requests.get('https://discord.com/api/v10/users/@me', headers=headers)

    if resp.status_code != 200:
        return render_template('index.html', error='Invalid user token'), 401

    user_data = resp.json()
    client_ip = get_client_ip()

    # Check if IP has changed (for security)
    if 'login_ip' in session and session['login_ip'] != client_ip:
        # IP changed - clear old session and create new one
        session.clear()

    # Store session data
    session.permanent = True
    session['user_token'] = user_token
    session['user'] = user_data
    session['login_ip'] = client_ip

    # Initialize sent_count if not exists
    if 'sent_count' not in session:
        session['sent_count'] = 0

    # Log the login (you can store this in a database later)
    print(f"[LOGIN] User: {user_data.get('username')} (ID: {user_data.get('id')}) | IP: {client_ip}")

    return redirect(url_for('panel'))

@app.route('/panel')
def panel():
    if 'user_token' not in session:
        return redirect(url_for('login_page'))

    # Check if IP has changed
    client_ip = get_client_ip()
    if 'login_ip' in session and session['login_ip'] != client_ip:
        session.clear()
        return redirect(url_for('login_page'))

    user_token = session.get('user_token')
    headers = {'Authorization': user_token}

    # Fetch user's guilds
    resp = requests.get('https://discord.com/api/v10/users/@me/guilds', headers=headers)

    if resp.status_code != 200:
        session.clear()
        return redirect(url_for('index'))

    guilds = resp.json()
    response = app.make_response(render_template('dashboard.html', user=session['user'], guilds=guilds))
    # Prevent caching of dashboard page
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/api/guild/<guild_id>/channels')
def get_guild_channels(guild_id):
    if 'user_token' not in session:
        return {'error': 'Unauthorized'}, 401

    user_token = session.get('user_token')
    headers = {'Authorization': user_token}

    try:
        # Fetch channels for this guild
        resp = requests.get(
            f'https://discord.com/api/v10/guilds/{guild_id}/channels',
            headers=headers,
            timeout=10
        )

        if resp.status_code == 200:
            channels = resp.json()
            # Filter and return only text channels
            text_channels = [ch for ch in channels if ch.get('type') == 0]
            return {'channels': text_channels}, 200
        elif resp.status_code == 401:
            # Token is invalid, clear session
            session.clear()
            return {'error': 'Session expired'}, 401
        else:
            return {'error': 'Failed to fetch channels'}, resp.status_code
    except requests.exceptions.Timeout:
        return {'error': 'Request timeout'}, 500
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/send-message-single', methods=['POST'])
def send_message_single():
    if 'user_token' not in session:
        return {'error': 'Unauthorized'}, 401

    user_token = session.get('user_token')
    headers = {'Authorization': user_token, 'Content-Type': 'application/json'}

    data = request.json
    channel = data.get('channel', {})
    message_content = data.get('message', '').strip()

    if not message_content:
        return {'error': 'Message cannot be empty'}, 400

    if not channel:
        return {'error': 'No channel provided'}, 400

    channel_id = channel.get('id')
    channel_name = channel.get('name')

    try:
        resp = requests.post(
            f'https://discord.com/api/v10/channels/{channel_id}/messages',
            headers=headers,
            json={'content': message_content},
            timeout=10
        )

        if resp.status_code == 200 or resp.status_code == 201:
            # Track successful send immediately in session
            if 'sent_count' not in session:
                session['sent_count'] = 0
            session['sent_count'] += 1
            session.modified = True
            return {'success': True, 'channel': channel_name}, 200
        elif resp.status_code == 429:
            # Extract retry_after from Discord's response
            try:
                rate_limit_data = resp.json()
                retry_after = rate_limit_data.get('retry_after', 1.0)  # Discord returns seconds as float
                # Convert to milliseconds for JavaScript
                retry_after_ms = int(retry_after * 1000)
            except:
                retry_after_ms = 1000  # Default to 1 second
            return {'success': False, 'error': 'Rate limited', 'retry_after': retry_after_ms}, 429
        else:
            try:
                error_msg = resp.json().get('message', 'Unknown error')
            except:
                error_msg = f'HTTP {resp.status_code}'
            return {'success': False, 'error': error_msg}, resp.status_code
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Request timeout'}, 500
    except Exception as e:
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/send-message', methods=['POST'])
def send_message():
    if 'user_token' not in session:
        return {'error': 'Unauthorized'}, 401

    user_token = session.get('user_token')
    headers = {'Authorization': user_token, 'Content-Type': 'application/json'}

    data = request.json
    channels = data.get('channels', [])
    message_content = data.get('message', '').strip()

    if not message_content:
        return {'error': 'Message cannot be empty'}, 400

    if not channels:
        return {'error': 'No channels selected'}, 400

    results = {'success': [], 'failed': []}

    for channel in channels:
        channel_id = channel.get('id')
        channel_name = channel.get('name')

        try:
            resp = requests.post(
                f'https://discord.com/api/v10/channels/{channel_id}/messages',
                headers=headers,
                json={'content': message_content},
                timeout=10
            )

            if resp.status_code == 200 or resp.status_code == 201:
                results['success'].append(channel_name)
                # Track successful send
                if 'sent_count' not in session:
                    session['sent_count'] = 0
                session['sent_count'] += 1
            elif resp.status_code == 429:
                results['failed'].append(f'{channel_name} (Rate limited)')
            else:
                try:
                    error_msg = resp.json().get('message', 'Unknown error')
                except:
                    error_msg = f'HTTP {resp.status_code}'
                results['failed'].append(f'{channel_name} ({error_msg})')
        except requests.exceptions.Timeout:
            results['failed'].append(f'{channel_name} (Request timeout)')
        except Exception as e:
            results['failed'].append(f'{channel_name} ({str(e)})')

    return results, 200

@app.route('/settings')
def settings():
    if 'user_token' not in session:
        return redirect(url_for('login_page'))

    # Check if IP has changed
    client_ip = get_client_ip()
    if 'login_ip' in session and session['login_ip'] != client_ip:
        session.clear()
        return redirect(url_for('login_page'))

    sent_count = session.get('sent_count', 0)
    response = app.make_response(render_template('settings.html', user=session['user'], sent_count=sent_count))
    # Prevent caching of settings page
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/logout')
def logout():
    session.clear()
    response = app.make_response(render_template('logout.html'))
    # Prevent caching to avoid going back to dashboard after logout
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=True)
