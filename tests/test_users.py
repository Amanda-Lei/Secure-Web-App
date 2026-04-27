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
        "active": True,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time()
    },
    "chris": {
        "username": "chris",
        "email": "chris@test.com",
        "password_hash": hash_pw("Ilovecompsec123!"),
        "role": "user",
        "active": True,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time()
    },
    "admin": {
        "username": "admin",
        "email": "admin@test.com",
        "password_hash": hash_pw("Password123!"),
        "role": "admin",
        "active": True,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time()
    },
    "old": {
        "username": "old",
        "email": "old@test.com",
        "password_hash": hash_pw("Disabled123!"),
        "role": "user",
        "active": False,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time()
    }
}

storage.save_encrypted(users_file, users)
print("Test users created.")