# Homepage Slideshow Configuration Guide

## Config File Location
**File to edit:** `homepage_config.py`

This file controls the hero section slideshow on the homepage.

## Configuration Options

### 1. Slideshow Interval
```python
SLIDESHOW_INTERVAL = 4000  # Time between slides in milliseconds
```

**How it works:**
- The value is in milliseconds (1000ms = 1 second)
- Default: `4000` (4 seconds between each slide)
- Recommended range: 3000-6000 (3-6 seconds)

**Examples:**
- `SLIDESHOW_INTERVAL = 3000` - Changes every 3 seconds (fast)
- `SLIDESHOW_INTERVAL = 5000` - Changes every 5 seconds (comfortable)
- `SLIDESHOW_INTERVAL = 8000` - Changes every 8 seconds (slow)

### 2. Fade Duration
```python
SLIDESHOW_FADE_DURATION = 300  # Fade in/out duration in milliseconds
```

**How it works:**
- Controls how long the fade-out and fade-in animations take
- The value is in milliseconds (1000ms = 1 second)
- Default: `300` (0.3 seconds)
- Recommended range: 200-500 (0.2-0.5 seconds)

**Examples:**
- `SLIDESHOW_FADE_DURATION = 200` - Quick fade (0.2 seconds)
- `SLIDESHOW_FADE_DURATION = 300` - Standard fade (0.3 seconds)
- `SLIDESHOW_FADE_DURATION = 500` - Slow fade (0.5 seconds)

**Important:**
- Total transition time = `SLIDESHOW_FADE_DURATION * 2` (fade out + fade in)
- Faster fades (200-300ms) feel snappier
- Slower fades (400-500ms) feel more elegant

### 3. Slideshow Messages
```python
SLIDESHOW_MESSAGES = [
    "First message to display",
    "Second message to display",
    "Third message to display"
]
```

**How it works:**
- Add as many messages as you want to the list
- Messages are displayed in order, then loop back to the first
- Each message fades out and the next fades in smoothly
- Messages are displayed exactly as written

**Rules:**
- Each message must be in quotes (single `'` or double `"` quotes)
- Separate messages with commas
- At least 1 message is required
- No maximum limit on messages

## Examples

### Example 1: Fast Slideshow with 3 Messages
```python
SLIDESHOW_INTERVAL = 3000  # 3 seconds

SLIDESHOW_MESSAGES = [
    "The fastest Discord marketing tool",
    "Reach thousands instantly",
    "One click, unlimited potential"
]
```

### Example 2: Slow Slideshow with Many Messages
```python
SLIDESHOW_INTERVAL = 6000  # 6 seconds

SLIDESHOW_MESSAGES = [
    "The first marketing tool to send multiple advertisements all across discord with one click",
    "Reach thousands of Discord servers instantly",
    "Automate your Discord marketing campaigns effortlessly",
    "Grow your community with powerful bulk messaging",
    "Save hours with automated multi-server posting",
    "Professional Discord marketing made simple"
]
```

### Example 3: Single Static Message (No Slideshow)
```python
SLIDESHOW_INTERVAL = 999999  # Very long interval (effectively static)

SLIDESHOW_MESSAGES = [
    "The first marketing tool to send multiple advertisements all across discord with one click"
]
```
**Note:** With only one message, the slideshow won't cycle, so the interval doesn't matter.

## Layout and Button Position

The hero section is designed to keep the "View Pricing" button in a fixed position:
- The text area has a minimum height of 6em
- This prevents the button from moving when text changes
- Works with messages of varying lengths

## Tips

1. **Message Length:** Keep messages concise for better readability
2. **Timing:** Match interval to message length (longer messages = longer interval)
3. **Consistency:** Use similar message lengths for smooth visual flow
4. **Testing:** Reload the homepage after changes to see the effect
5. **Restart Required:** After editing `homepage_config.py`, restart the Flask app

## How to Apply Changes

1. Open `homepage_config.py`
2. Edit `SLIDESHOW_INTERVAL`, `SLIDESHOW_FADE_DURATION`, and/or `SLIDESHOW_MESSAGES`
3. Save the file
4. Restart the Flask application
5. Refresh your browser at http://127.0.0.1:5000

The slideshow will start automatically when you load the homepage!

## Complete Configuration Example

```python
# Homepage Configuration
SLIDESHOW_INTERVAL = 5000  # 5 seconds between slides
SLIDESHOW_FADE_DURATION = 400  # 0.4 second fade

SLIDESHOW_MESSAGES = [
    "The first marketing tool to send multiple advertisements all across discord with one click",
    "Reach thousands of Discord servers instantly",
    "Automate your Discord marketing campaigns effortlessly"
]
```
