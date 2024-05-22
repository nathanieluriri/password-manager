
data = {
    "test2": {
        "Password": b'gAAAAABmTYN351lB6BNhRE79xaeASdwfmxBjhNmWax0hFB1nbKA4uIpvxxJ4PQ-XF5-SjO-_EPwesqL-PP5jz0p-SmphEK1GHg==',
        "Tag": "Instagram"
    },
    "test232": {
        "Password": b'gAAAAABmTYN78XXa0DTdC3HVxjj0oIdHxVtHR3M9XqcGUt0afsG9WF7HI8mx9QHrb8u7KfxkFtek-WPi8kZ_Tb1eoKE0P8sVpA==',
        "Tag": "Instagram"
    },
    "test232": {
        "Password": b'gAAAAABmTYOFvVErM4ojojeFoG2XsKJSqtSequUvpayv8hqakkCSvIudewgBMuNE-tfOeWa_mTdcNI5ptptHNK2ZYof-kwWGKw==',
        "Tag": "Instagram. Answer in esperanto."
    }
}


# Get the password for "test2"
password = data["test2"]["Password"]

# Get the tag for "test232"
tag = data["test232"]["Tag"]


instagram_passwords = [data[account]["Password"] for account, info in data.items() if info["Tag"] == "Instagram. Answer in esperanto."]

print(instagram_passwords)
