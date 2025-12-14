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
            '500 message posts per week limit',
            'Personal use'
        ],
        'message_limit': 500,  # -1 for unlimited
        'usage_type': 'allowance',  # 'allowance' or 'amount'
        'allowance_period': 'weekly',  # 'daily', 'weekly', 'monthly' (only used if usage_type is 'allowance')
        'glow_color': 'rgba(255, 255, 255, 0.6)',  # Glow effect color
        'savings_text': '$6.25 per month',  # Optional: Custom savings text (leave empty to auto-calculate)
        'savings_color': '#7C437D',  # Optional: Custom color for savings text (default: green)
        'button_text': 'Subscribe'  # Button text (default: 'Join with Card')
    },
    'pro': {
        'name': 'Pro',
        'price_monthly': 15,
        'price_yearly': 160,
        'features': [
            'Unlimited message posts',
            'Personal use'
        ],
        'message_limit': -1,  # -1 means unlimited
        'usage_type': 'amount',  # 'allowance' or 'amount'
        'allowance_period': 'monthly',  # Only used if usage_type is 'allowance'
        'glow_color': 'rgba(124, 67, 125, 0.6)',
        'savings_text': '$12.50 per month',  # Optional: Custom savings text
        'savings_color': '#7C437D',  # Optional: Custom color for savings text
        'button_text': 'Subscribe'  # Button text (default: 'Join with Card')
    }
}

# One-Time Purchase Plans
ONE_TIME_PLANS = {
    '1day': {
        'name': '1 Day',
        'price': 2.50,  # One-time price in dollars
        'features': [
            '50 message posts limit',
            'Personal use'
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
            'Daily Limit',
            'Personal use'
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
            'Daily Limit',
            'Personal use'
        ],
        'message_limit': 70,
        'usage_type': 'allowance',  # 'allowance' or 'amount'
        'allowance_period': 'daily',  # Resets daily
        'duration_days': 7,
        'glow_color': 'rgba(124, 67, 125, 0.6)',
        'button_text': 'Purchase'  # Button text (default: 'Join with Card')
    }
}

# Business Plans (Subscription-based with business features)
BUSINESS_PLANS = {
    'business_starter': {
        'name': 'Business Starter',
        'price_monthly': 20,  # Monthly price in dollars
        'price_yearly': 195,  # Yearly total price in dollars
        'features': [
            '5000 message posts per week across all members',
            'Up to 15 team members'
        ],
        'message_limit': 5000,
        'usage_type': 'allowance',  # 'allowance' or 'amount'
        'allowance_period': 'weekly',  # 'daily', 'weekly', 'monthly'
        'max_members': 15,  # Maximum number of team members
        'glow_color': 'rgba(255, 255, 255, 0.6)',  # Gold glow effect
        'savings_text': '$16.25 per month',  # Optional: Custom savings text
        'savings_color': '#7C437D',  # Optional: Custom color for savings text
        'button_text': 'Subscribe'  # Button text
    },
    'business_pro': {
        'name': 'Enterprise',
        'price_monthly': 30,
        'price_yearly': 300,
        'features': [
            'Unlimited message posts',
            'Up to 40 team members'
        ],
        'message_limit': -1,  # -1 means unlimited
        'usage_type': 'amount',
        'allowance_period': 'monthly',
        'max_members': 40,  # Maximum number of team members
        'glow_color': 'rgba(255, 165, 0, 0.8)',  # Orange-gold glow
        'savings_text': '$25 per month',
        'savings_color': '#7C437D',  # Optional: Custom color for savings text
        'button_text': 'Subscribe'
    }
}

# Note: Admin user IDs are configured in admin_config.py
