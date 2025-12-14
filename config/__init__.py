# =============================================================================
# CONFIG PACKAGE
# =============================================================================
# Import all configs from this folder for easy access.
# Usage: from config import BUTTONS, HOMEPAGE, SITE, etc.
# =============================================================================

from .buttons import BUTTONS
from .homepage import HOMEPAGE
from .navbar import NAVBAR
from .colors import COLORS
from .pages import PAGES
from .text import TEXT
from .plans import SUBSCRIPTION_PLANS, ONE_TIME_PLANS, BUSINESS_PLANS
from .admin import ADMIN_USER_IDS, is_admin
from .database_version import DATABASE_VERSION, DATABASE_WIPE_MESSAGE

# Import site-wide settings
from .site import (
    SITE_FONT,
    HEADING_FONT,
    CODE_FONT,
    BASE_FONT_SIZE,
    LINE_HEIGHT,
    SITE_NAME,
    SITE_DESCRIPTION,
    COPYRIGHT_TEXT,
    MAX_CONTENT_WIDTH,
    BORDER_RADIUS,
    SPACING_UNIT,
    ANIMATIONS_ENABLED,
    TRANSITION_DURATION,
    TRANSITION_EASING,
)


def get_all_config():
    """Return all configuration as a single dictionary for template injection."""
    return {
        'buttons': BUTTONS,
        'homepage': HOMEPAGE,
        'navbar': NAVBAR,
        'colors': COLORS,
        'pages': PAGES,
        'text': TEXT,
        # Backwards compatibility aliases
        'page_titles': PAGES['titles'],
    }


# Dictionary of site-wide settings for easy template access
SITE = {
    'font': SITE_FONT,
    'heading_font': HEADING_FONT or SITE_FONT,
    'code_font': CODE_FONT,
    'base_font_size': BASE_FONT_SIZE,
    'line_height': LINE_HEIGHT,
    'name': SITE_NAME,
    'description': SITE_DESCRIPTION,
    'copyright': COPYRIGHT_TEXT,
    'max_width': MAX_CONTENT_WIDTH,
    'border_radius': BORDER_RADIUS,
    'spacing': SPACING_UNIT,
    'animations': ANIMATIONS_ENABLED,
    'transition_duration': TRANSITION_DURATION,
    'transition_easing': TRANSITION_EASING,
}
