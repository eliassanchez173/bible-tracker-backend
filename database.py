import os
import psycopg2
import psycopg2.extras

def get_db():
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS readings (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            book TEXT NOT NULL,
            chapter INTEGER NOT NULL,
            date TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    cursor.close()
    conn.close()