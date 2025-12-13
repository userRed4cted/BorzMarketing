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


def check_message_content(message, user_id=None):
    """
    Check if message contains any blacklisted content.
    Returns (is_valid, reason) tuple.
    If user_id is provided and blacklisted content is found, flags the user.
    """
    if not message or not message.strip():
        return False, "Message cannot be empty"

    message_lower = message.lower()

    # Check whitelist first
    for whitelisted in WHITELIST:
        if whitelisted.lower() in message_lower:
            return True, None

    # Check blacklist - find ALL prohibited words
    found_words = []
    for word in BLACKLISTED_WORDS:
        if word.lower() in message_lower:
            found_words.append(word)

    if found_words:
        # Create comprehensive flag reason with all prohibited words and full message
        prohibited_list = "', '".join(found_words)
        reason = f"Prohibited content: '{prohibited_list}'\n\nFull message:\n{message}"

        # Flag the user if user_id is provided
        if user_id:
            try:
                from database import flag_user
                flag_user(user_id, reason)
            except Exception as e:
                print(f"[WARNING] Failed to flag user {user_id}: {e}")

        # Return error message with ALL prohibited words to user
        if len(found_words) == 1:
            error_msg = f"Message contains prohibited content: '{found_words[0]}'"
        else:
            error_msg = f"Message contains prohibited content: '{prohibited_list}'"
        return False, error_msg

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
