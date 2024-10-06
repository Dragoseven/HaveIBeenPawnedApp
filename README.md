# Password Strength and Pwned Checker

This Python application provides a graphical user interface (GUI) for checking password strength and whether a password has been compromised in known data breaches. It combines a password strength checker with the "Have I Been Pwned" API to give users comprehensive feedback on their password security.

## Features

- **Password Strength Checker**: Evaluates the strength of a given password based on various criteria.
- **"Have I Been Pwned" Integration**: Checks if a password has appeared in known data breaches using the "Have I Been Pwned" API.
- **Multi-window Interface**: Separates the password strength checker and the pwned password checker into two windows for a cleaner user experience.
- **Password Visibility Toggle**: Allows users to show or hide the password they're entering.

## Requirements

- Python 3.x
- tkinter (usually comes pre-installed with Python)
- requests library

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/password-checker.git
   cd password-checker
   ```

2. Install the required libraries:
   ```
   pip install requests
   ```

## Usage

Run the script using Python:

```
python password_checker.py
```

1. The main window will open, showing the Password Strength Checker.
2. Enter a password in the provided field and click "Check Strength" to evaluate its strength.
3. Click the "Open Second Window" button to access the "Have I Been Pwned" checker.
4. In the second window, enter a password and click "Check Password" to see if it has appeared in known data breaches.

## How It Works

### Password Strength Checker

The password strength is evaluated based on the following criteria:
- Length (at least 8 characters)
- Presence of uppercase letters
- Presence of lowercase letters
- Presence of numbers
- Presence of special characters

### "Have I Been Pwned" Checker

This feature uses the "Have I Been Pwned" API to check if a password has appeared in known data breaches. It works as follows:
1. The password is hashed using SHA-1.
2. Only the first 5 characters of the hash are sent to the API for privacy reasons.
3. The API returns a list of suffix hashes that match the prefix.
4. The application checks if the full hash of the password is in the returned list.

## Security Note

This application never sends your full password or its complete hash over the network. It uses the k-Anonymity model to protect your password's privacy while still checking if it has been compromised.

## Contributing

Contributions, issues, and feature requests are welcome. Big shoutout to @Steves-Coding-Lab for the base code and YT Video for inspiration and guidance on this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
