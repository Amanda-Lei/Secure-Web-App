from security import EncryptedStorage
import bcrypt
import time

storage = EncryptedStorage()
users_file = "data/users.json"

def hash_pw(pw):
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

users = {
    "amanda": {
        "username": "amanda",
        "email": "amanda@test.com",
        "password_hash": hash_pw("I1!qwertyuiop"),
        "role": "user",
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time()
    },
    "chris": {
        "username": "chris",
        "email": "chris@test.com",
        "password_hash": hash_pw("Ilovecompsec123!"),
        "role": "user",
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time()
    },
    "admin": {
        "username": "admin",
        "email": "admin@test.com",
        "password_hash": hash_pw("Password123!"),
        "role": "admin",
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time()
    }
}

storage.save_encrypted(users_file, users)
print("Test users created.")