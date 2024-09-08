import sqlite3
import os
import jwt
import bcrypt
import datetime

def get_db_connection():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(current_dir, '..', 'database.db')
    connection = sqlite3.connect(db_path)
    
    return connection


def signup(name, email, role, password):
    # Encrypt the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Insert the user into the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        INSERT INTO users (name, email, role, password)
        VALUES (?, ?, ?, ?)
    ''', (name, email, role, hashed_password))
    conn.commit()
    conn.close()
    
    # Create a JWT token
    payload = {
        'email': email,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=10)  # Token expires in 1 day
    }
    token = jwt.encode(payload, "officehours", algorithm='HS256')
    
    return True, token

def login(email, password):
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Retrieve the email and password from the database
    cursor.execute('SELECT email, password, role FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user is None:
        return False,'User not found'
    
    # Unpack the user data
    db_email, hashed_password, role = user
    
    # Verify the password
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        # Create a JWT token
        payload = {
            'email': db_email,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expires in 1 day
        }
        token = jwt.encode(payload, 'officehours', algorithm='HS256')
        return True, token
    else:
        return False, 'Invalid password'


def createOfficeHour(datetime1, lec, questions, prof_email, location):
    # Write code to insert values into officehours table.
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO officehours (datetime, class, questions, prof_email, location)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime1, lec, questions, prof_email, location))
        conn.commit()
        print("Office hour inserted successfully.")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
   
    token = signup('John Doe', 'john@example.com', 'user', 'securepassword123')
    print(f"Signup successful. JWT token: {token}")

    login_token = login('john@example.com', 'securepassword123')
    print(f"Login successful. JWT token: {login_token}")