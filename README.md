# Borz Marketing Panel

A Discord marketing automation web application with OAuth2 authentication.

## Features

- Discord OAuth2 login
- Multi-server message broadcasting
- Subscription and one-time purchase plans
- Business team management
- Admin panel for user management
- Mobile-responsive design

## Setup Instructions

### 1. Create Discord Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application"
3. Go to "OAuth2" > "General"
4. Copy your **Client ID** and **Client Secret**
5. In "OAuth2" > "Redirects", add: `http://localhost:5000/callback`

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Create `.env` File

Create a `.env` file in the project root:

```
DISCORD_CLIENT_ID=your_client_id_here
DISCORD_CLIENT_SECRET=your_client_secret_here
SECRET_KEY=your_random_secret_key_here
```

### 4. Run the Application

```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Project Structure

```
borz_adveristing_website/
├── app.py                    # Flask application
├── requirements.txt          # Python dependencies
├── config/                   # Configuration files
│   ├── __init__.py          # Config exports
│   ├── admin.py             # Admin user IDs
│   ├── buttons.py           # Button text config
│   ├── colors.py            # Color theme config
│   ├── database_version.py  # DB version for wipe notices
│   ├── homepage.py          # Homepage content config
│   ├── navbar.py            # Navigation config
│   ├── pages.py             # Page titles config
│   ├── plans.py             # Pricing plans config
│   ├── site.py              # Site-wide settings (fonts, etc.)
│   └── text.py              # UI text/labels config
├── database/                 # Database utilities
│   └── models.py            # Database models and operations
├── security/                 # Security utilities
│   ├── auth.py              # Authentication & validation
│   └── content_filter.py    # Message content filtering
├── templates/                # Jinja2 HTML templates
├── static/                   # CSS, JS files
└── RESET_DATABASE.py         # Database reset script
```

## Configuration

All configuration is in the `config/` folder:

- **plans.py** - Pricing plans and features
- **homepage.py** - Homepage slideshow and content
- **navbar.py** - Navigation menu labels
- **text.py** - UI text and labels
- **site.py** - Site-wide settings (fonts, layout, animations)
- **admin.py** - Admin user Discord IDs
- **database_version.py** - Database wipe notification version

See the individual config files for detailed settings.

## Database Management

### Reset Database
Run `python RESET_DATABASE.py` to:
1. **Reset** - Clear all data but keep table structure
2. **Delete** - Remove database file entirely

Both options increment the database version, which triggers a notification for all users.

## Security Notes

- Keep your `.env` file private (add to `.gitignore`)
- Never commit Discord credentials
- User tokens are encrypted before storage
