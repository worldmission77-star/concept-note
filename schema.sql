DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    grade TEXT NOT NULL,
    student_phone TEXT,
    parent_phone TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    note_date TEXT NOT NULL,
    content TEXT,
    photo_filename TEXT,
    feedback TEXT,
    checked_at TIMESTAMP,
    parent_token TEXT UNIQUE,
    parent_checked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
