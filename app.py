from flask import Flask, render_template, redirect, url_for, session, request
import os
from dotenv import load_dotenv
import requests
import uuid
from datetime import timedelta
from database import (
    init_db, create_user, get_user_by_discord_id, get_user_by_id, update_user_token,
    set_subscription, get_active_subscription, can_send_message,
    record_successful_send, get_plan_status, update_user_session,
    validate_user_session, save_user_data, get_user_data,
    get_all_users_for_admin, get_user_admin_details, ban_user, unban_user,
    flag_user, unflag_user, delete_user_account_admin
)
from homepage_config import SLIDESHOW_MESSAGES, SLIDESHOW_INTERVAL, SLIDESHOW_FADE_DURATION
from content_filter import check_message_content, BLACKLISTED_WORDS
from admin_config import is_admin

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Session security configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # 30 days session
app.config['SESSION_PERMANENT'] = True

# Discord OAuth2 configuration
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
DISCORD_REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI', 'http://127.0.0.1:5000/callback')
DISCORD_API_BASE = 'https://discord.com/api/v10'
DISCORD_OAUTH_URL = f'https://discord.com/api/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={DISCORD_REDIRECT_URI}&response_type=code&scope=identify%20guilds'

# OAuth credentials loaded from environment variables

# Initialize database
init_db()

# Helper function to get client IP
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

# Helper function to check business access
def has_business_access(user_id, discord_id):
    """Check if user has access to business features (owner or member)."""
    from database import get_business_team_by_owner, get_business_team_by_member

    # Check if user owns a business team
    team = get_business_team_by_owner(user_id)
    if team:
        return True

    # Check if user is a member of a business team
    team = get_business_team_by_member(discord_id)
    if team:
        return True

    return False

def fetch_discord_user_info(discord_id):
    """Fetch user information from Discord API using bot token."""
    bot_token = os.getenv('DISCORD_BOT_TOKEN')

    if not bot_token:
        return None, None

    try:
        headers = {'Authorization': f'Bot {bot_token}'}
        response = requests.get(f'{DISCORD_API_BASE}/users/{discord_id}', headers=headers, timeout=5)

        if response.status_code == 200:
            discord_user = response.json()
            username = discord_user.get('username', 'Unknown User')
            avatar = discord_user.get('avatar', '')
            print(f"[DISCORD API] Successfully fetched user info for {discord_id}: {username}")
            return username, avatar
        else:
            print(f"[DISCORD API] Failed to fetch user {discord_id}: Status {response.status_code}, Response: {response.text}")
            return None, None
    except requests.exceptions.Timeout:
        print(f"[DISCORD API] Timeout fetching user {discord_id}")
        return None, None
    except Exception as e:
        print(f"[DISCORD API] Error fetching user {discord_id}: {str(e)}")
        return None, None

# Session validation before each request
@app.before_request
def validate_session():
    """Validate user session before each request (single session enforcement)."""
    # Skip validation for static files, login, signup, callback, and home page
    if request.endpoint in ['static', 'login_page', 'signup_page', 'callback', 'home', 'root']:
        return

    # Check if user is logged in
    if 'user' in session and 'session_id' in session:
        discord_id = session['user']['id']
        session_id = session['session_id']

        # Validate session ID against database
        if not validate_user_session(discord_id, session_id):
            # Session invalid - clear session and redirect to home
            session.clear()
            return redirect(url_for('home'))

# CSP headers removed - they were blocking JavaScript execution

@app.route('/')
def root():
    return redirect(url_for('home'))

@app.route('/home')
def home():
    # Get plan status if user is logged in
    plan_status = None
    has_business = False
    is_admin_user = False
    if 'user' in session:
        user = get_user_by_discord_id(session['user']['id'])
        if user:
            plan_status = get_plan_status(user['id'])
            # Check if user has business access (owner or member)
            from database import is_business_plan_owner, is_business_team_member
            has_business = is_business_plan_owner(user['id']) or is_business_team_member(session['user']['id'])
            # Check if user is admin
            is_admin_user = is_admin(session['user']['id'])

    return render_template('home.html',
                         slideshow_messages=SLIDESHOW_MESSAGES,
                         slideshow_interval=SLIDESHOW_INTERVAL,
                         slideshow_fade_duration=SLIDESHOW_FADE_DURATION,
                         plan_status=plan_status,
                         has_business=has_business,
                         is_admin_user=is_admin_user)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        # Direct OAuth login (from navbar button)
        return redirect(DISCORD_OAUTH_URL)

    # POST request handling (token-based login)
    user_token = request.form.get('user_token', '').strip()

    if not user_token:
        return render_template('index.html', error='Discord token is required'), 400

    # Store token temporarily to verify with OAuth2
    session['pending_token'] = user_token
    session['is_signup_flow'] = False  # Mark this as a login flow

    # Redirect to Discord OAuth
    return redirect(DISCORD_OAUTH_URL)

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'GET':
        if 'user_token' in session:
            return redirect(url_for('panel'))

        # Check for signup error from login redirect
        error = session.pop('signup_error', None)

        response = app.make_response(render_template('signup.html', error=error))
        # Prevent caching of signup page
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    # POST request handling
    user_token = request.form.get('user_token', '').strip()

    if not user_token:
        return render_template('signup.html', error='Discord token is required'), 400

    # Store token temporarily to verify with OAuth2
    session['pending_token'] = user_token
    session['is_signup_flow'] = True  # Mark this as a signup flow

    # Redirect to OAuth2 for verification
    return redirect(DISCORD_OAUTH_URL)

@app.route('/callback')
def oauth_callback():
    print("[CALLBACK] Callback route hit")

    # Get the authorization code from the callback
    code = request.args.get('code')
    error = request.args.get('error')

    if error:
        print(f"[CALLBACK] OAuth2 error: {error}")
        return redirect(url_for('home'))

    if not code:
        print("[CALLBACK] No code provided, redirecting to home")
        return redirect(url_for('home'))

    print(f"[CALLBACK] Received code: {code[:20]}...")

    # Exchange code for access token
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        # Get access token
        print("[CALLBACK] Exchanging code for token...")
        token_response = requests.post(f'{DISCORD_API_BASE}/oauth2/token', data=data, headers=headers)
        print(f"[CALLBACK] Token response status: {token_response.status_code}")

        if token_response.status_code != 200:
            print(f"[CALLBACK] Token exchange failed: {token_response.text}")
            return redirect(url_for('home'))

        token_data = token_response.json()
        access_token = token_data.get('access_token')

        # Get user information
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        print("[CALLBACK] Fetching user info...")
        user_response = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=auth_headers)
        print(f"[CALLBACK] User info response status: {user_response.status_code}")

        if user_response.status_code != 200:
            print(f"[CALLBACK] User info fetch failed: {user_response.text}")
            return redirect(url_for('home'))

        user_data = user_response.json()
        discord_id = user_data.get('id')
        username = user_data.get('username')
        avatar = user_data.get('avatar')
        print(f"[CALLBACK] User: {username} (ID: {discord_id})")

        # Get client IP
        client_ip = get_client_ip()
        print(f"[CALLBACK] Client IP: {client_ip}")

        # Check if this is a token verification flow (login or signup with token)
        print(f"[CALLBACK] Checking session - pending_token: {'pending_token' in session}, is_signup_flow: {session.get('is_signup_flow', False)}")

        if 'pending_token' in session:
            pending_token = session['pending_token']
            is_signup_flow = session.get('is_signup_flow', False)
            print(f"[CALLBACK] Token verification flow - signup: {is_signup_flow}")

            # Verify the pending token matches this user
            # Test the pending token by making an API call
            test_headers = {'Authorization': pending_token}
            test_response = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=test_headers)

            if test_response.status_code != 200:
                session.pop('pending_token', None)
                session.pop('is_signup_flow', None)
                error_template = 'signup.html' if is_signup_flow else 'index.html'
                return render_template(error_template, error='Invalid Discord token. Please check your token and try again.')

            test_user_data = test_response.json()
            test_discord_id = test_user_data.get('id')

            # Verify the token belongs to the OAuth2 authenticated user
            if test_discord_id != discord_id:
                session.pop('pending_token', None)
                session.pop('is_signup_flow', None)
                error_template = 'signup.html' if is_signup_flow else 'index.html'
                return render_template(error_template, error='Token does not match your Discord account. Please use your own token.')

            # Check if user already exists
            existing_user = get_user_by_discord_id(discord_id)

            if existing_user:
                # User already exists
                if is_signup_flow:
                    # This is signup - show error
                    session.pop('pending_token', None)
                    session.pop('is_signup_flow', None)
                    return render_template('signup.html', error='Account already exists. Please login instead.')
                else:
                    # This is login - update their token and log them in
                    update_user_token(discord_id, pending_token)
                    print(f"[LOGIN] User logged in with token: {username} (ID: {discord_id}) | IP: {client_ip}")

                    # Generate new session ID and store in database
                    new_session_id = str(uuid.uuid4())
                    update_user_session(discord_id, new_session_id)

                    # Store session data
                    session.permanent = True
                    session['user_token'] = pending_token
                    session['user'] = user_data
                    session['login_ip'] = client_ip
                    session['session_id'] = new_session_id
                    session.pop('pending_token', None)
                    session.pop('is_signup_flow', None)

                    # Initialize sent_count
                    if 'sent_count' not in session:
                        session['sent_count'] = 0

                    return redirect(url_for('home'))
            else:
                # User doesn't exist
                if not is_signup_flow:
                    # This is login - redirect to signup
                    session.pop('pending_token', None)
                    session.pop('is_signup_flow', None)
                    session['signup_error'] = 'No account found. Please sign up first.'
                    return redirect(url_for('signup_page'))

                # This is signup - create new user
                create_user(discord_id, username, avatar, pending_token, client_ip)
                print(f"[SIGNUP] New user created: {username} (ID: {discord_id}) | IP: {client_ip}")

                # Generate new session ID and store in database
                new_session_id = str(uuid.uuid4())
                update_user_session(discord_id, new_session_id)

                # Store session data
                session.permanent = True
                session['user_token'] = pending_token
                session['user'] = user_data
                session['login_ip'] = client_ip
                session['session_id'] = new_session_id
                session.pop('pending_token', None)
                session.pop('is_signup_flow', None)

                # Initialize sent_count
                if 'sent_count' not in session:
                    session['sent_count'] = 0

                return redirect(url_for('home'))

        else:
            # Regular login flow (no pending token)
            print("[CALLBACK] Regular login flow (no pending token)")
            # Check if user already exists
            existing_user = get_user_by_discord_id(discord_id)
            print(f"[CALLBACK] Login flow - Discord ID: {discord_id}, User exists: {existing_user is not None}")

            if not existing_user:
                # User doesn't exist, redirect to signup page
                print(f"[LOGIN] No user found for Discord ID: {discord_id}, redirecting to signup")
                session['signup_error'] = 'No account found. Please sign up first.'
                return redirect(url_for('signup_page'))

            # User exists, log them in with their stored Discord token
            user_token = existing_user['discord_token']
            print(f"[LOGIN] Existing user via OAuth2: {username} (ID: {discord_id}) | IP: {client_ip}")
            print(f"[DEBUG] Setting session - user_token length: {len(user_token) if user_token else 0}")

            # Generate new session ID and store in database (invalidates other sessions)
            new_session_id = str(uuid.uuid4())
            update_user_session(discord_id, new_session_id)

            # Store session data
            session.permanent = True
            session['user_token'] = user_token
            session['user'] = user_data
            session['login_ip'] = client_ip
            session['session_id'] = new_session_id

            # Initialize sent_count if not exists
            if 'sent_count' not in session:
                session['sent_count'] = 0

            return redirect(url_for('home'))

    except Exception as e:
        print(f"[ERROR] OAuth2 callback error: {str(e)}")
        return redirect(url_for('home'))

@app.route('/purchase')
def purchase():
    from config import SUBSCRIPTION_PLANS, ONE_TIME_PLANS, BUSINESS_PLANS, YEARLY_DISCOUNT_PERCENT

    # Get plan status if user is logged in
    plan_status = None
    has_business = False
    is_admin_user = False
    if 'user' in session:
        user = get_user_by_discord_id(session['user']['id'])
        if user:
            plan_status = get_plan_status(user['id'])
            has_business = has_business_access(user['id'], session['user']['id'])
            is_admin_user = is_admin(session['user']['id'])

    return render_template('purchase.html',
                         subscription_plans=SUBSCRIPTION_PLANS,
                         one_time_plans=ONE_TIME_PLANS,
                         business_plans=BUSINESS_PLANS,
                         yearly_discount=YEARLY_DISCOUNT_PERCENT,
                         plan_status=plan_status,
                         has_business=has_business,
                         is_admin_user=is_admin_user)

@app.route('/api/set-plan', methods=['POST'])
def set_plan():
    """API endpoint to activate a plan for a user."""
    from config import SUBSCRIPTION_PLANS, ONE_TIME_PLANS, BUSINESS_PLANS
    from flask import jsonify

    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    data = request.get_json()
    plan_type = data.get('plan_type')  # 'subscription', 'one-time', or 'business'
    plan_id = data.get('plan_id')
    billing_period = data.get('billing_period')  # 'monthly' or 'yearly' (for subscriptions only)

    # Validate plan type
    if plan_type not in ['subscription', 'one-time', 'business']:
        return jsonify({'success': False, 'error': 'Invalid plan type'}), 400

    # Get plan configuration
    if plan_type == 'subscription':
        if plan_id not in SUBSCRIPTION_PLANS:
            return jsonify({'success': False, 'error': 'Invalid subscription plan'}), 400
        if billing_period not in ['monthly', 'yearly']:
            return jsonify({'success': False, 'error': 'Invalid billing period'}), 400
        plan_config = SUBSCRIPTION_PLANS[plan_id]
    elif plan_type == 'business':
        if plan_id not in BUSINESS_PLANS:
            return jsonify({'success': False, 'error': 'Invalid business plan'}), 400
        if billing_period not in ['monthly', 'yearly']:
            return jsonify({'success': False, 'error': 'Invalid billing period'}), 400
        plan_config = BUSINESS_PLANS[plan_id]
    else:
        if plan_id not in ONE_TIME_PLANS:
            return jsonify({'success': False, 'error': 'Invalid one-time plan'}), 400
        plan_config = ONE_TIME_PLANS[plan_id]
        billing_period = None  # One-time plans don't have billing periods

    # Get user from database
    user = get_user_by_discord_id(session['user']['id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found in database'}), 404

    try:
        # Activate the plan
        set_subscription(user['id'], plan_type, plan_id, plan_config, billing_period)
        print(f"[PLAN] Plan activated for {session['user']['username']}: {plan_config['name']} ({plan_type})")

        # If it's a business plan, create a business team
        redirect_url = '/panel'
        if plan_type == 'business':
            from database import create_business_team, get_active_subscription
            subscription = get_active_subscription(user['id'])
            if subscription:
                max_members = plan_config.get('max_members', 3)
                create_business_team(user['id'], subscription['id'], max_members)
                redirect_url = '/business-management'

        return jsonify({
            'success': True,
            'message': f"{plan_config['name']} plan activated!",
            'redirect_url': redirect_url
        }), 200
    except Exception as e:
        print(f"[ERROR] Plan activation error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to activate plan'}), 500

@app.route('/panel')
def panel():
    if 'user_token' not in session:
        return redirect(url_for('login_page'))

    # Check if IP has changed
    client_ip = get_client_ip()
    if 'login_ip' in session and session['login_ip'] != client_ip:
        session.clear()
        return redirect(url_for('login_page'))

    # Check if user has an active plan
    user = get_user_by_discord_id(session['user']['id'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))

    # Check if user is banned
    if user.get('banned', 0) == 1:
        session.clear()
        return redirect(url_for('home'))

    plan_status = get_plan_status(user['id'])
    if not plan_status['has_plan']:
        # Redirect to purchase page if no active plan
        return redirect(url_for('purchase'))

    # Block business plan holders from accessing personal panel
    if plan_status.get('plan_id', '').startswith('business_'):
        # Redirect business plan holders to purchase page
        return redirect(url_for('purchase'))

    user_token = session.get('user_token')
    headers = {'Authorization': user_token}

    # Fetch user's guilds
    resp = requests.get('https://discord.com/api/v10/users/@me/guilds', headers=headers)

    if resp.status_code != 200:
        session.clear()
        return redirect(url_for('home'))

    guilds = resp.json()

    # Get user data (includes message_delay)
    user_data = get_user_data(user['id'])

    # Check if user has business access
    has_business = has_business_access(user['id'], session['user']['id'])

    # Check if user is admin
    is_admin_user = is_admin(session['user']['id'])

    response = app.make_response(render_template('dashboard.html', user=session['user'], guilds=guilds, plan_status=plan_status, user_data=user_data, has_business=has_business, is_admin_user=is_admin_user, BLACKLISTED_WORDS=BLACKLISTED_WORDS))
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

    # Check usage limits
    user = get_user_by_discord_id(session['user']['id'])
    if not user:
        return {'error': 'User not found'}, 404

    can_send, reason, remaining = can_send_message(user['id'])
    if not can_send:
        return {'error': f'Cannot send message: {reason}', 'limit_reached': True}, 403

    user_token = session.get('user_token')
    headers = {'Authorization': user_token, 'Content-Type': 'application/json'}

    data = request.json
    channel = data.get('channel', {})
    message_content = data.get('message', '').strip()

    # Check content filter and flag user if needed
    is_valid, filter_reason = check_message_content(message_content, user['id'])
    if not is_valid:
        return {'error': filter_reason}, 400

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
            # Track successful send in database
            record_successful_send(user['id'])
            # Also update session for backward compatibility
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

    # Get user for limit checking and flagging
    user = get_user_by_discord_id(session['user']['id'])
    if not user:
        return {'error': 'User not found'}, 404

    # Check content filter and flag user if needed
    is_valid, filter_reason = check_message_content(message_content, user['id'])
    if not is_valid:
        return {'error': filter_reason}, 400

    if not channels:
        return {'error': 'No channels selected'}, 400

    results = {'success': [], 'failed': []}

    for channel in channels:
        # Check if user can still send before each message
        can_send, reason, remaining = can_send_message(user['id'])
        if not can_send:
            results['failed'].append(f'{channel.get("name")} (Limit reached: {reason})')
            continue

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
                # Track successful send in database
                record_successful_send(user['id'])
                # Also update session for backward compatibility
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

@app.route('/business-management')
def business_management():
    """Business plan management page for team owners."""
    if 'user_token' not in session:
        return redirect(url_for('login_page'))

    client_ip = get_client_ip()
    if 'login_ip' in session and session['login_ip'] != client_ip:
        session.clear()
        return redirect(url_for('login_page'))

    user = get_user_by_discord_id(session['user']['id'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))

    # Check if user is banned
    if user.get('banned', 0) == 1:
        session.clear()
        return redirect(url_for('home'))

    # Check if user owns a business plan
    from database import get_business_team_by_owner, get_team_members, get_team_member_stats, update_team_member_info
    team = get_business_team_by_owner(user['id'])

    if not team:
        return redirect(url_for('purchase'))

    # Get team members
    members = get_team_members(team['id'])

    # Refresh Discord info for members who show as "Unknown User"
    for member in members:
        if member['member_username'] == 'Unknown User' or not member['member_username']:
            username, avatar = fetch_discord_user_info(member['member_discord_id'])
            if username:
                update_team_member_info(team['id'], member['member_discord_id'], username, avatar)
                print(f"[BUSINESS] Updated member info for {member['member_discord_id']}: {username}")

    # Get member stats including usage (refetch after potential updates)
    member_stats = get_team_member_stats(team['id'])
    plan_status = get_plan_status(user['id'])

    # User has business access (they're on this page)
    has_business = True

    # Check if user is admin
    is_admin_user = is_admin(session['user']['id'])

    return render_template('business.html',
                         user=session['user'],
                         team=team,
                         members=members,
                         member_stats=member_stats,
                         plan_status=plan_status,
                         has_business=has_business,
                         is_admin_user=is_admin_user,
                         BLACKLISTED_WORDS=BLACKLISTED_WORDS)

@app.route('/business-panel')
def business_panel():
    """Business panel for team members to send messages."""
    if 'user_token' not in session:
        return redirect(url_for('login_page'))

    client_ip = get_client_ip()
    if 'login_ip' in session and session['login_ip'] != client_ip:
        session.clear()
        return redirect(url_for('login_page'))

    user = get_user_by_discord_id(session['user']['id'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))

    # Check if user is banned
    if user.get('banned', 0) == 1:
        session.clear()
        return redirect(url_for('home'))

    # Check if user is team owner or member
    from database import get_business_team_by_owner, get_business_team_by_member
    team = get_business_team_by_owner(user['id'])

    if not team:
        team = get_business_team_by_member(session['user']['id'])

    if not team:
        return redirect(url_for('purchase'))

    plan_status = get_plan_status(user['id'])

    # Get Discord guilds
    user_token = session.get('user_token')
    headers = {'Authorization': user_token}
    resp = requests.get('https://discord.com/api/v10/users/@me/guilds', headers=headers)

    if resp.status_code != 200:
        session.clear()
        return redirect(url_for('home'))

    guilds = resp.json()

    # Get user data
    user_data = get_user_data(user['id'])

    # User has business access (they're on this page)
    has_business = True

    # Check if user is admin
    is_admin_user = is_admin(session['user']['id'])

    response = app.make_response(render_template('business-panel.html',
                                                user=session['user'],
                                                guilds=guilds,
                                                team=team,
                                                plan_status=plan_status,
                                                user_data=user_data,
                                                has_business=has_business,
                                                is_admin_user=is_admin_user,
                                                BLACKLISTED_WORDS=BLACKLISTED_WORDS))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/settings')
def settings():
    if 'user_token' not in session:
        return redirect(url_for('login_page'))

    # Check if IP has changed
    client_ip = get_client_ip()
    if 'login_ip' in session and session['login_ip'] != client_ip:
        session.clear()
        return redirect(url_for('login_page'))

    # Get user from database
    user = get_user_by_discord_id(session['user']['id'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))

    # Get plan status information
    plan_status = get_plan_status(user['id'])
    sent_count = session.get('sent_count', 0)

    # Get user data (includes message_delay)
    user_data = get_user_data(user['id'])

    # Check if user has business access and get business plan status
    has_business = has_business_access(user['id'], session['user']['id'])
    business_plan_status = None

    if has_business:
        from database import get_business_team_by_owner, get_business_team_by_member, get_business_plan_status
        # Check if owner
        team = get_business_team_by_owner(user['id'])
        if team:
            # User is owner - get aggregated business plan status
            business_plan_status = get_business_plan_status(team['id'], user['id'])
        else:
            # User is member - get owner's business plan status with aggregated usage
            team = get_business_team_by_member(session['user']['id'])
            if team:
                business_plan_status = get_business_plan_status(team['id'], team['owner_user_id'])

    # Check if user is admin
    is_admin_user = is_admin(session['user']['id'])

    response = app.make_response(render_template('settings.html',
                                                user=session['user'],
                                                sent_count=sent_count,
                                                plan_status=plan_status,
                                                user_data=user_data,
                                                has_business=has_business,
                                                is_admin_user=is_admin_user,
                                                business_plan_status=business_plan_status))
    # Prevent caching of settings page
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/api/cancel-plan', methods=['POST'])
def cancel_plan():
    from flask import jsonify
    from database import cancel_subscription

    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    try:
        user = get_user_by_discord_id(session['user']['id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        # Cancel the subscription
        cancel_subscription(user['id'])
        print(f"[PLAN] Plan cancelled for {session['user']['username']}")

        return jsonify({'success': True}), 200

    except Exception as e:
        print(f"[ERROR] Cancel plan error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/save-user-data', methods=['POST'])
def api_save_user_data():
    """Save user's selected channels, draft message, and/or message delay."""
    from flask import jsonify

    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    try:
        user = get_user_by_discord_id(session['user']['id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        data = request.get_json()
        selected_channels = data.get('selected_channels')
        draft_message = data.get('draft_message')
        message_delay = data.get('message_delay')

        # Check content filter for draft message and flag user if needed
        if draft_message and draft_message.strip():
            is_valid, filter_reason = check_message_content(draft_message, user['id'])
            if not is_valid:
                return jsonify({'success': False, 'error': filter_reason}), 400

        # Save to database
        save_user_data(user['id'], selected_channels, draft_message, message_delay)

        return jsonify({'success': True}), 200

    except Exception as e:
        print(f"[ERROR] Save user data error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/get-user-data', methods=['GET'])
def api_get_user_data():
    """Get user's selected channels and draft message."""
    from flask import jsonify

    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    try:
        user = get_user_by_discord_id(session['user']['id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        # Get from database
        user_data = get_user_data(user['id'])

        return jsonify({
            'success': True,
            'data': user_data
        }), 200

    except Exception as e:
        print(f"[ERROR] Get user data error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/delete-account', methods=['POST'])
def delete_account():
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        user_data = session.get('user')
        discord_id = user_data.get('id')

        # Delete user from database (this will cascade delete subscriptions and usage)
        from database import delete_user
        delete_user(discord_id)

        # Clear localStorage data on client side
        # This is done on the client side after successful deletion

        # Log the deletion
        print(f"[DELETE] Account deleted: {user_data.get('username')} (ID: {discord_id})")

        # Clear session
        session.clear()

        return {'success': True}, 200

    except Exception as e:
        print(f"[ERROR] Delete account error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/business/add-member', methods=['POST'])
def add_business_member():
    """Add a member to the business team."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        user = get_user_by_discord_id(session['user']['id'])
        if not user:
            return {'success': False, 'error': 'User not found'}, 404

        # Check if user owns a business team
        from database import get_business_team_by_owner, get_team_member_count, add_team_member
        team = get_business_team_by_owner(user['id'])

        if not team:
            return {'success': False, 'error': 'No business team found'}, 404

        data = request.get_json()
        member_discord_id = data.get('discord_id')

        if not member_discord_id:
            return {'success': False, 'error': 'Discord ID required'}, 400

        # Check if trying to add own Discord ID
        owner_discord_id = session['user']['id']
        if member_discord_id == owner_discord_id:
            return {'success': False, 'error': 'Cannot add yourself as a team member'}, 400

        # Check if the user being added is banned
        from database import get_user_by_discord_id as get_user_check
        member_user = get_user_check(member_discord_id)
        if member_user and member_user.get('banned', 0) == 1:
            return {'success': False, 'error': 'This user is banned and cannot be added to teams'}, 403

        # Check if team is full
        current_count = get_team_member_count(team['id'])
        if current_count >= team['max_members']:
            return {'success': False, 'error': f"Team is full (max {team['max_members']} members)"}, 400

        # Fetch user info from Discord API
        username, avatar = fetch_discord_user_info(member_discord_id)

        # If Discord API failed, use fallback values
        if not username:
            username = 'Unknown User'
            avatar = ''

        # Add member with Discord info
        success = add_team_member(team['id'], member_discord_id, username, avatar)

        if success:
            return {'success': True, 'message': 'Member added successfully'}, 200
        else:
            return {'success': False, 'error': 'Member already exists'}, 400

    except Exception as e:
        print(f"[ERROR] Add member error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/business/remove-member', methods=['POST'])
def remove_business_member():
    """Remove a member from the business team."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        user = get_user_by_discord_id(session['user']['id'])
        if not user:
            return {'success': False, 'error': 'User not found'}, 404

        # Check if user owns a business team
        from database import get_business_team_by_owner, remove_team_member
        team = get_business_team_by_owner(user['id'])

        if not team:
            return {'success': False, 'error': 'No business team found'}, 404

        data = request.get_json()
        member_discord_id = data.get('discord_id')

        if not member_discord_id:
            return {'success': False, 'error': 'Discord ID required'}, 400

        remove_team_member(team['id'], member_discord_id)
        return {'success': True, 'message': 'Member removed successfully'}, 200

    except Exception as e:
        print(f"[ERROR] Remove member error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/business/set-team-message', methods=['POST'])
def set_team_message():
    """Set the team message for business panel."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        user = get_user_by_discord_id(session['user']['id'])
        if not user:
            return {'success': False, 'error': 'User not found'}, 404

        # Check if user owns a business team
        from database import get_business_team_by_owner, update_team_message
        team = get_business_team_by_owner(user['id'])

        if not team:
            return {'success': False, 'error': 'No business team found'}, 404

        data = request.get_json()
        message = data.get('message', '')

        # Check content filter and flag user if needed (only if message is not empty)
        if message and message.strip():
            is_valid, filter_reason = check_message_content(message, user['id'])
            if not is_valid:
                return {'success': False, 'error': filter_reason}, 400

        update_team_message(team['id'], message)
        return {'success': True, 'message': 'Team message updated successfully'}, 200

    except Exception as e:
        print(f"[ERROR] Set team message error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500


# Team invitation API endpoints

@app.route('/api/team/invitations', methods=['GET'])
def get_invitations():
    """Get pending team invitations for the current user."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        from database import get_team_invitations
        invitations = get_team_invitations(session['user']['id'])
        return {'success': True, 'invitations': invitations}, 200

    except Exception as e:
        print(f"[ERROR] Get invitations error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500


@app.route('/api/team/invitation/accept/<int:member_id>', methods=['POST'])
def accept_invitation(member_id):
    """Accept a team invitation."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        from database import accept_team_invitation, get_team_invitations, deny_team_invitation

        # Get all invitations for this user
        invitations = get_team_invitations(session['user']['id'])

        # Check if this invitation belongs to the user
        invitation = next((inv for inv in invitations if inv['id'] == member_id), None)
        if not invitation:
            return {'success': False, 'error': 'Invitation not found'}, 404

        # Accept this invitation
        accept_team_invitation(member_id)

        # Deny all other pending invitations for this user
        for inv in invitations:
            if inv['id'] != member_id:
                deny_team_invitation(inv['id'])

        return {'success': True, 'message': 'Invitation accepted'}, 200

    except Exception as e:
        print(f"[ERROR] Accept invitation error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500


@app.route('/api/team/invitation/deny/<int:member_id>', methods=['POST'])
def deny_invitation(member_id):
    """Deny a team invitation."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        from database import deny_team_invitation, get_team_invitations

        # Verify this invitation belongs to the user
        invitations = get_team_invitations(session['user']['id'])
        invitation = next((inv for inv in invitations if inv['id'] == member_id), None)
        if not invitation:
            return {'success': False, 'error': 'Invitation not found'}, 404

        deny_team_invitation(member_id)
        return {'success': True, 'message': 'Invitation denied'}, 200

    except Exception as e:
        print(f"[ERROR] Deny invitation error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500


@app.route('/api/team/invitations/clear', methods=['POST'])
def clear_invitations():
    """Clear all pending invitations for the current user."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        from database import clear_all_invitations
        clear_all_invitations(session['user']['id'])
        return {'success': True, 'message': 'All invitations cleared'}, 200

    except Exception as e:
        print(f"[ERROR] Clear invitations error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500


@app.route('/api/team/leave', methods=['POST'])
def leave_team_route():
    """Leave the current team."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        from database import leave_team, get_current_team_for_member

        # Check if user is in a team
        team = get_current_team_for_member(session['user']['id'])
        if not team:
            return {'success': False, 'error': 'Not in any team'}, 404

        leave_team(session['user']['id'])
        return {'success': True, 'message': 'Left team successfully'}, 200

    except Exception as e:
        print(f"[ERROR] Leave team error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500


@app.route('/api/team/member/remove/<int:member_id>', methods=['POST'])
def remove_member_from_list(member_id):
    """Remove a team member from the list (owner only, for denied/left members)."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    try:
        user = get_user_by_discord_id(session['user']['id'])
        if not user:
            return {'success': False, 'error': 'User not found'}, 404

        from database import get_business_team_by_owner, remove_team_member_from_list, get_team_members

        # Check if user owns a business team
        team = get_business_team_by_owner(user['id'])
        if not team:
            return {'success': False, 'error': 'No business team found'}, 404

        # Verify this member belongs to this team
        members = get_team_members(team['id'])
        member = next((m for m in members if m['id'] == member_id), None)
        if not member:
            return {'success': False, 'error': 'Member not found'}, 404

        # Can only remove denied or left members
        if member['invitation_status'] not in ['denied', 'left']:
            return {'success': False, 'error': 'Can only remove denied or left members'}, 400

        remove_team_member_from_list(member_id)
        return {'success': True, 'message': 'Member removed from list'}, 200

    except Exception as e:
        print(f"[ERROR] Remove member from list error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500


@app.route('/admin')
def admin_panel():
    """Admin panel page."""
    if 'user' not in session:
        return redirect(url_for('login_page'))

    # Check if IP has changed
    client_ip = get_client_ip()
    if 'login_ip' in session and session['login_ip'] != client_ip:
        session.clear()
        return redirect(url_for('login_page'))

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return redirect(url_for('home'))

    # Get user from database
    user = get_user_by_discord_id(session['user']['id'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))

    plan_status = get_plan_status(user['id'])
    has_business = has_business_access(user['id'], session['user']['id'])
    is_admin_user = True  # They're already on the admin page

    response = app.make_response(render_template('admin.html',
                                                user=session['user'],
                                                plan_status=plan_status,
                                                has_business=has_business,
                                                is_admin_user=is_admin_user))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    """Get all users with optional filters."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        # Get filters from query params
        filters = []
        if request.args.get('non_plan') == 'true':
            filters.append('non_plan')
        if request.args.get('plan') == 'true':
            filters.append('plan')
        if request.args.get('banned') == 'true':
            filters.append('banned')
        if request.args.get('flagged') == 'true':
            filters.append('flagged')

        users = get_all_users_for_admin(filters if filters else None)
        return {'success': True, 'users': users}, 200

    except Exception as e:
        print(f"[ERROR] Admin get users error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/search-user', methods=['GET'])
def admin_search_user():
    """Search for a user by Discord ID."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        discord_id = request.args.get('discord_id')
        if not discord_id:
            return {'success': False, 'error': 'Discord ID required'}, 400

        # Search for user by discord_id
        user = get_user_by_discord_id(discord_id)
        if not user:
            return {'success': False, 'error': 'User not found'}, 404

        # Get has_plan status
        from database import get_active_subscription
        subscription = get_active_subscription(user['id'])
        user['has_plan'] = 1 if subscription else 0

        # Check if user is admin
        user['is_admin'] = is_admin(discord_id)

        # Fetch fresh Discord profile info
        username, avatar = fetch_discord_user_info(discord_id)
        if username:
            # Update user info in database
            from database import update_user_profile
            update_user_profile(user['id'], username, avatar)
            user['username'] = username
            user['avatar'] = avatar

        return {'success': True, 'user': user}, 200

    except Exception as e:
        print(f"[ERROR] Admin search user error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/user/<int:user_id>', methods=['GET'])
def admin_get_user_details(user_id):
    """Get detailed user information."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        user_details = get_user_admin_details(user_id)
        if not user_details:
            return {'success': False, 'error': 'User not found'}, 404

        # Fetch fresh Discord profile info
        username, avatar = fetch_discord_user_info(user_details['discord_id'])
        if username:
            # Update user info in database
            from database import update_user_profile
            update_user_profile(user_id, username, avatar)
            user_details['username'] = username
            user_details['avatar'] = avatar

        return {'success': True, 'user': user_details}, 200

    except Exception as e:
        print(f"[ERROR] Admin get user details error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/ban/<int:user_id>', methods=['POST'])
def admin_ban_user(user_id):
    """Ban a user."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        ban_user(user_id)
        return {'success': True, 'message': 'User banned successfully'}, 200

    except Exception as e:
        print(f"[ERROR] Admin ban user error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/unban/<int:user_id>', methods=['POST'])
def admin_unban_user(user_id):
    """Unban a user."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        unban_user(user_id)
        return {'success': True, 'message': 'User unbanned successfully'}, 200

    except Exception as e:
        print(f"[ERROR] Admin unban user error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/flag/<int:user_id>', methods=['POST'])
def admin_flag_user(user_id):
    """Flag a user."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        flag_user(user_id)
        return {'success': True, 'message': 'User flagged successfully'}, 200

    except Exception as e:
        print(f"[ERROR] Admin flag user error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/unflag/<int:user_id>', methods=['POST'])
def admin_unflag_user(user_id):
    """Unflag a user."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        unflag_user(user_id)
        return {'success': True, 'message': 'User unflagged successfully'}, 200

    except Exception as e:
        print(f"[ERROR] Admin unflag user error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    """Delete a user account."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        delete_user_account_admin(user_id)
        return {'success': True, 'message': 'User deleted successfully'}, 200

    except Exception as e:
        print(f"[ERROR] Admin delete user error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/user/<int:user_id>/message', methods=['GET'])
def admin_get_user_message(user_id):
    """Get user's saved draft message from their panel."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        # Get user_data which contains draft_message
        user_data = get_user_data(user_id)
        if not user_data:
            return {'success': True, 'message': 'No message saved'}, 200

        draft_message = user_data.get('draft_message', '')
        return {'success': True, 'message': draft_message or 'No message saved'}, 200

    except Exception as e:
        print(f"[ERROR] Admin get user message error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/admin/user/<int:user_id>/team-message', methods=['GET'])
def admin_get_team_message(user_id):
    """Get business team message if user is owner or member."""
    if 'user' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401

    # Check if user is admin
    if not is_admin(session['user']['id']):
        return {'success': False, 'error': 'Unauthorized'}, 403

    try:
        from database import get_business_team_by_owner, get_user_by_id
        user_data = get_user_by_id(user_id)
        if not user_data:
            return {'success': False, 'error': 'User not found'}, 404

        # Check if user owns a business team
        team = get_business_team_by_owner(user_id)
        if not team:
            # Check if user is a member
            from database import get_business_team_by_member
            team = get_business_team_by_member(user_data['discord_id'])

        if not team:
            return {'success': False, 'error': 'User is not part of any business team'}, 404

        team_message = team.get('team_message', '')
        return {'success': True, 'message': team_message or 'No team message set'}, 200

    except Exception as e:
        print(f"[ERROR] Admin get team message error: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

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
