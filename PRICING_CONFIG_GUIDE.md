# Purchase Page Configuration Guide

## Config File Location
**File to edit:** `config.py`

This file controls all pricing, features, and plan details for the purchase page.

## Configuration Options

### 1. Yearly Discount Percentage
```python
YEARLY_DISCOUNT_PERCENT = 17  # This means 17% off when paying yearly
```
- This applies to ALL subscription plans
- When users toggle to "Yearly", prices are calculated automatically
- The discount badge shows: "Save 17%"
- The yearly savings text shows: "SAVING $XXX (17% OFF) YEARLY"

### 2. Subscription Plans

Each subscription plan has the following configurable options:

```python
SUBSCRIPTION_PLANS = {
    'plan_id': {
        'name': 'Plan Name',           # Display name (will be uppercase)
        'price_monthly': 9.99,          # Monthly price in dollars (supports decimals: 9.99 or whole numbers: 10)
        'price_yearly': 99.99,          # Yearly total price in dollars
        'features': [                   # List of features to display
            'Feature 1',
            'Feature 2',
            'Feature 3'
        ],
        'message_limit': -1,            # -1 for unlimited, or a number for limit
        'usage_type': 'allowance',      # 'allowance' (resets) or 'amount' (fixed total)
        'allowance_period': 'monthly',  # 'daily', 'weekly', 'monthly' (only for allowance type)
        'glow_color': 'rgba(51, 95, 255, 0.6)',  # Glow effect color (RGBA)
        'button_text': 'Subscribe'      # Button text (customizable)
    }
}
```

**Important Notes:**
- `price_monthly`: Regular monthly price (supports decimals like 9.99 or whole numbers like 10)
- `price_yearly`: Total yearly price (used to calculate monthly price when yearly is selected)
- When yearly is selected, the displayed price = `price_yearly / 12`
- Savings calculation = `(price_monthly * 12) - price_yearly`
- Features are displayed exactly as written in the list
- `usage_type`: Controls how message limits work
  - `'allowance'` - Limit resets after the specified period (daily/weekly/monthly)
  - `'amount'` - Fixed total for entire plan duration, no resets
- `allowance_period`: Only used when usage_type is 'allowance'
  - Options: `'daily'`, `'weekly'`, `'monthly'`

### 3. One-Time Purchase Plans

Each one-time plan has the following options:

```python
ONE_TIME_PLANS = {
    'plan_id': {
        'name': '1 Day License',        # Display name
        'price': 2.99,                  # One-time price in dollars (supports decimals: 2.99 or whole numbers: 3)
        'features': [                   # List of features to display
            '1 day access',
            '5 messages/day',
            'Multi-server support'
        ],
        'message_limit': 5,             # Messages allowed
        'usage_type': 'amount',         # 'allowance' (resets) or 'amount' (fixed total)
        'allowance_period': None,       # 'daily', 'weekly', 'monthly' or None (for amount type)
        'duration_days': 1,             # How many days the plan lasts
        'glow_color': 'rgba(100, 255, 100, 0.6)',  # Glow effect color
        'button_text': 'Purchase'       # Button text (customizable)
    }
}
```

## How Pricing Works

### Monthly Subscription Display
- Shows: `$9.99 PER MONTH`
- Uses the `price_monthly` value directly

### Yearly Subscription Display
- Shows: `$8.33 PER MONTH` (if price_yearly is $99.99)
- Calculation: `price_yearly / 12` rounded to 2 decimals
- Also shows: `SAVING $20 (17% OFF) YEARLY`
- Savings = `(price_monthly * 12) - price_yearly`

### One-Time Plans Display
- Shows: `$2.99`
- Uses the `price` value directly
- No monthly/yearly toggle

## Examples

### Example 1: Basic Subscription Plan
```python
'starter': {
    'name': 'Starter',
    'price_monthly': 15.00,
    'price_yearly': 150.00,
    'features': [
        '100 messages/month',
        '5 servers',
        'Email support'
    ],
    'message_limit': 100,
    'glow_color': 'rgba(0, 150, 255, 0.6)',
    'icon': '🚀'
}
```

Result:
- Monthly: Shows `$15.00 PER MONTH`
- Yearly: Shows `$12.50 PER MONTH` with `SAVING $30 (17% OFF) YEARLY`

### Example 2: Unlimited Plan
```python
'unlimited': {
    'name': 'Unlimited',
    'price_monthly': 50.00,
    'price_yearly': 499.20,
    'features': [
        'Unlimited messages',
        'Unlimited servers',
        'Priority support',
        'Custom branding'
    ],
    'message_limit': -1,  # -1 means unlimited
    'glow_color': 'rgba(255, 215, 0, 0.8)',
    'icon': '💎'
}
```

### Example 3: One-Time Plan
```python
'weekend': {
    'name': 'Weekend Pass',
    'price': 5.99,
    'features': [
        '2 days access',
        '10 messages/day',
        'All servers'
    ],
    'message_limit': 10,
    'duration_days': 2,
    'glow_color': 'rgba(255, 100, 100, 0.6)',
    'icon': '⚡'
}
```

## Color Guide for Glow Effects

Use RGBA colors for the glow effect:
- `rgba(R, G, B, A)` where:
  - R, G, B are 0-255 (red, green, blue)
  - A is 0-1 (transparency, 0.6 recommended)

Common colors:
- Blue: `rgba(51, 95, 255, 0.6)`
- Gold: `rgba(255, 215, 0, 0.6)`
- Green: `rgba(100, 255, 100, 0.6)`
- Purple: `rgba(150, 100, 255, 0.6)`
- Red: `rgba(255, 100, 100, 0.6)`
- Cyan: `rgba(100, 200, 255, 0.6)`

## Pricing Format

### Decimal vs Whole Number Prices

The purchase page automatically handles both decimal and whole number prices:

**Decimal Prices** (with cents):
```python
'price': 2.99   # Displays as: $2.99
'price': 9.50   # Displays as: $9.50
```

**Whole Number Prices**:
```python
'price': 5      # Displays as: $5 (no decimals)
'price': 10.00  # Displays as: $10 (no decimals)
```

The system automatically detects if a price has decimal values and displays them accordingly.

## Tips

1. **Keep feature lists concise** - 3-5 features per plan is ideal
2. **Use clear feature names** - Be specific about what's included
3. **Price format** - Use numbers like `9.99` or `10`, not strings like `"$9.99"`
4. **Decimal prices** - Automatically displayed when price has cents (e.g., 2.50 shows as $2.50)
5. **Whole prices** - Automatically displayed without decimals (e.g., 5 shows as $5)
6. **Test your changes** - Save the file and refresh the purchase page
7. **Yearly pricing** - Make sure `price_yearly` is less than `price_monthly * 12` to show savings
8. **Usage types** - See [USAGE_TYPES_GUIDE.md](USAGE_TYPES_GUIDE.md) for detailed usage type configuration
