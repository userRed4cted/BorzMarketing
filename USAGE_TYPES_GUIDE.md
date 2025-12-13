# Usage Types Configuration Guide

## Overview
The usage types system allows you to control how message limits are applied and reset for each plan.

## Usage Types

### 1. Allowance
**Usage:** `'usage_type': 'allowance'`

With allowance type, the message limit resets after a specified time period. This is ideal for subscription plans where users get a fresh allowance regularly.

**Required Field:** `'allowance_period'`

**Available Periods:**
- `'daily'` - Resets every day at midnight
- `'weekly'` - Resets every week (Monday at midnight)
- `'monthly'` - Resets every month (1st of the month at midnight)

**Example:**
```python
'regular': {
    'name': 'Regular',
    'price_monthly': 7,
    'price_yearly': 75,
    'message_limit': 1000,
    'usage_type': 'allowance',
    'allowance_period': 'monthly',  # Resets on the 1st of each month
}
```

**How it works:**
- User gets 1000 messages per month
- On the 1st of each month, their usage count resets to 0
- They can send up to 1000 messages again

### 2. Amount
**Usage:** `'usage_type': 'amount'`

With amount type, the message limit is a fixed total for the entire plan duration with NO resets. Once used up, no more messages can be sent until the plan expires or is renewed.

**Required Field:** `'allowance_period': None`

**Example:**
```python
'1day': {
    'name': '1 Day Pass',
    'price': 2.50,
    'message_limit': 50,
    'usage_type': 'amount',
    'allowance_period': None,  # No reset
    'duration_days': 1,
}
```

**How it works:**
- User gets a total of 50 messages for the entire 1-day period
- Once they send 50 messages, they cannot send more
- The count does NOT reset during the plan period
- Only resets when they purchase a new plan

## Configuration Examples

### Example 1: Monthly Subscription with Monthly Reset
```python
'pro': {
    'name': 'Pro',
    'price_monthly': 15,
    'price_yearly': 160,
    'message_limit': 5000,
    'usage_type': 'allowance',
    'allowance_period': 'monthly',  # Resets every month
}
```
User gets 5000 messages per month. Resets on the 1st of every month.

### Example 2: Daily Subscription with Daily Reset
```python
'daily': {
    'name': 'Daily Plan',
    'price_monthly': 10,
    'message_limit': 200,
    'usage_type': 'allowance',
    'allowance_period': 'daily',  # Resets every day
}
```
User gets 200 messages per day. Resets at midnight every day.

### Example 3: One-Time Purchase with Fixed Amount
```python
'weekend': {
    'name': '3 Day Pass',
    'price': 5,
    'message_limit': 150,
    'usage_type': 'amount',  # Fixed total, no reset
    'allowance_period': None,
    'duration_days': 3,
}
```
User gets 150 total messages for 3 days. Does NOT reset daily.

### Example 4: Unlimited Plan
```python
'unlimited': {
    'name': 'Unlimited',
    'price_monthly': 25,
    'message_limit': -1,  # -1 means unlimited
    'usage_type': 'allowance',
    'allowance_period': 'monthly',
}
```
User has unlimited messages. The usage_type and allowance_period are ignored when message_limit is -1.

## Important Notes

1. **Usage Only Counts Successful Sends**
   - Only successful message sends are counted towards the limit
   - Failed sends do NOT count against the user's allowance

2. **Unlimited Plans**
   - When `message_limit` is set to `-1`, the plan is unlimited
   - Usage type settings are ignored for unlimited plans

3. **One-Time Plans**
   - Can use either 'allowance' or 'amount' type
   - 'amount' is recommended for one-time purchases (no reset)
   - 'allowance' can be used if you want daily resets during the purchase period

4. **Subscription Plans**
   - Usually use 'allowance' type with monthly/weekly/daily resets
   - 'amount' can be used for subscriptions if you want no resets

## How to Change Usage Type

1. Open `config.py`
2. Find the plan you want to modify
3. Set the `usage_type` field:
   - `'allowance'` - For resetting limits
   - `'amount'` - For fixed total limits
4. If using 'allowance', set `allowance_period`:
   - `'daily'`, `'weekly'`, or `'monthly'`
5. If using 'amount', set `allowance_period` to `None`

## Testing Your Configuration

After changing usage types, test the following:
1. Purchase a plan
2. Send messages until you approach the limit
3. For 'allowance' type: Wait for the reset period and verify the count resets
4. For 'amount' type: Verify the count persists and doesn't reset
