# Amanda and Chris's Secure Web App

## Overview

This project is a secure web application built with Flask that allows users to register and log in. Once in, they can securely upload, download, and share documents. The application implements multiple security features including authentication, authorization, encryption, and logging.

## Features

### Authentication & Security

* User registration with password complexity requirements
* Secure password hashing using bcrypt
* Login system with:

  * Account lockout after 5 failed attempts (15 minutes)
  * Rate limiting (10 attempts per IP per minute)
* Session management using secure cookies
* Input validation and sanitization
* Logging of authentication events (success/failure)

### Authorization

* Role-based access control (RBAC)

  * Roles: guest, user, admin
* Protected routes using decorators
* Admin-only dashboard for managing users

### Document Management

* Upload documents (PDF, TXT, PNG, JPG)
* Files are encrypted before storage using Fernet
* Secure file download (with decryption)
* Document ownership and sharing system
* Access control:

  * Users can only access their own or shared files
  * Admin can access all files

### Admin Features

* View all users
* Change user roles (guest/user/admin)
* Enable/disable user accounts
* View all uploaded documents
* Delete documents

## Tech Stack

* Python (Flask)
* HTML/CSS (Bootstrap)
* JSON (file-based storage)
* bcrypt (password hashing)
* cryptography (Fernet encryption)

## Setup Instructions with HTTPS

1. Clone the repository
2. Install dependencies:

```
python3 -m pip install flask bcrypt cryptography
```

3. Generate Certificate

```
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

4. Run the app

```
python3 app.py
```
If the port is busy, change the port in app.py and use the new port when accessing the app.
```
if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)
```

5. Access the App at

```
https://127.0.0.1:5000
```

Your browser may show a warning due to the self-signed certificate but this is expected for local development.

## Security Considerations

* Passwords are never stored in plain text
* Files are encrypted before being saved
* File types and sizes are restricted
* Users cannot access unauthorized documents
* Rate limiting and lockout prevent brute-force attacks

## Authors

* Amanda Lei
* Chris Chan
