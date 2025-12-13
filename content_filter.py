# Content Filter Configuration
# Add words/phrases to block in advertisement messages

# Blacklisted words and phrases (case-insensitive)
BLACKLISTED_WORDS = [
    'child porn',
    'cp',
    'loli',
    'shota',
    'porn',
    'sex',
    'nigger',
    'nigga',
    'free nitro',
    'discord nitro free',
    'free money',
    'free robux',
    'teen'

]

# Whitelist - words that should be allowed even if they contain blacklisted substrings
WHITELIST = [
    # Add exceptions here
    # Example: 'legitimate phrase',
]


def check_message_content(message):
    """
    Check if message contains any blacklisted content.
    Returns (is_valid, reason) tuple.
    """
    if not message or not message.strip():
        return False, "Message cannot be empty"

    message_lower = message.lower()

    # Check whitelist first
    for whitelisted in WHITELIST:
        if whitelisted.lower() in message_lower:
            return True, None

    # Check blacklist
    for word in BLACKLISTED_WORDS:
        if word.lower() in message_lower:
            return False, f"Message contains prohibited content: '{word}'"

    return True, None


def get_blacklist_count():
    """Returns the number of blacklisted words."""
    return len(BLACKLISTED_WORDS)


def add_blacklisted_word(word):
    """Add a word to the blacklist (for dynamic updates)."""
    if word and word not in BLACKLISTED_WORDS:
        BLACKLISTED_WORDS.append(word)
        return True
    return False


def remove_blacklisted_word(word):
    """Remove a word from the blacklist (for dynamic updates)."""
    if word in BLACKLISTED_WORDS:
        BLACKLISTED_WORDS.remove(word)
        return True
    return False
