# Configuration file for Borz Marketing Panel
# Edit this file to customize your pricing plans and features

# Yearly Discount Percentage (applies to all subscription plans)
YEARLY_DISCOUNT_PERCENT = 17  # This means 17% off when paying yearly

# Usage Types:
# 'allowance' - Resets after a specified time period (e.g., daily, weekly, monthly)
# 'amount' - Fixed total amount for the entire plan duration, no reset

# Subscription Plans
SUBSCRIPTION_PLANS = {
    'regular': {
        'name': 'Regular',
        'price_monthly': 7,  # Monthly price in dollars
        'price_yearly': 75,  # Yearly total price in dollars (should show savings)
        'features': [
            '1000 message posts per week limit'
        ],
        'message_limit': 1000,  # -1 for unlimited
        'usage_type': 'allowance',  # 'allowance' or 'amount'
        'allowance_period': 'weekly',  # 'daily', 'weekly', 'monthly' (only used if usage_type is 'allowance')
        'glow_color': 'rgba(255, 255, 255, 0.6)',  # Glow effect color
        'savings_text': '$6.25 per month',  # Optional: Custom savings text (leave empty to auto-calculate)
        'button_text': 'Subscribe'  # Button text (default: 'Join with Card')
    },
    'pro': {
        'name': 'Pro',
        'price_monthly': 15,
        'price_yearly': 160,
        'features': [
            'Unlimited message posts'
        ],
        'message_limit': -1,  # -1 means unlimited
        'usage_type': 'amount',  # 'allowance' or 'amount'
        'allowance_period': 'monthly',  # Only used if usage_type is 'allowance'
        'glow_color': 'rgba(2188, 83, 207, 0.6)',
        'savings_text': '$12.50 per month',  # Optional: Custom savings text
        'button_text': 'Subscribe'  # Button text (default: 'Join with Card')
    }
}

# One-Time Purchase Plans
ONE_TIME_PLANS = {
    '1day': {
        'name': '1 Day',
        'price': 2.50,  # One-time price in dollars
        'features': [
            '50 message posts limit'
        ],
        'message_limit': 50,
        'usage_type': 'amount',  # 'allowance' or 'amount'
        'allowance_period': None,  # Not used for 'amount' type
        'duration_days': 1,
        'glow_color': 'rgba(255, 255, 255, 0.6)',
        'button_text': 'Purchase'  # Button text (default: 'Join with Card')
    },
    '3day': {
        'name': '3 Days',
        'price': 5,
        'features': [
            '50 message posts limit per day',
            'Daily Limit'
        ],
        'message_limit': 50,
        'usage_type': 'allowance',  # 'allowance' or 'amount'
        'allowance_period': 'daily',  # Resets daily
        'duration_days': 3,
        'glow_color': 'rgba(255, 255, 255, 0.6)',
        'button_text': 'Purchase'  # Button text (default: 'Join with Card')
    },
    '7day': {
        'name': '7 Days',
        'price': 7.50,
        'features': [
            '70 message posts limit per day',
            'Daily Limit'
        ],
        'message_limit': 70,
        'usage_type': 'allowance',  # 'allowance' or 'amount'
        'allowance_period': 'daily',  # Resets daily
        'duration_days': 7,
        'glow_color': 'rgba(188, 83, 207, 0.6)',
        'button_text': 'Purchase'  # Button text (default: 'Join with Card')
    }
}

# Admin User IDs (Discord IDs)
ADMIN_DISCORD_IDS = [
    # Add admin Discord IDs here
    # Example: '123456789012345678'
]
