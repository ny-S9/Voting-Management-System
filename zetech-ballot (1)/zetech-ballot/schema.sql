-- ============================================================
-- ZETECH ELECTRONIC BALLOT SYSTEM  -  Database Schema (SQLite)
-- Created automatically by app.py the first time it runs.
-- ============================================================

-- 1. STUDENTS: the school's student records. Students log in with
--    admission_number. password stays NULL until they activate the
--    account on the site (it is then stored hashed, never as plain text).
CREATE TABLE students (
    student_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    admission_number  TEXT    NOT NULL UNIQUE,
    full_name         TEXT    NOT NULL,
    email             TEXT    NOT NULL UNIQUE,
    phone_number      TEXT    NOT NULL,
    password          TEXT    DEFAULT NULL,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO students (admission_number, full_name, email, phone_number) VALUES
('DIT-03-0084/2026', 'Kariuki Susan',    'kariukisusan@students.zetech.ac.ke', '0748672922'),
('DIT-03-0085/2026', 'John Mwangi',      'johnmwangi@students.zetech.ac.ke',   '0712345678'),
('DIT-03-0086/2026', 'Amina Yusuf',      'aminayusuf@students.zetech.ac.ke',   '0723456789'),
('DIT-03-0087/2026', 'Brian Otieno',     'brianotieno@students.zetech.ac.ke',  '0734567890'),
('DIT-03-0088/2026', 'Cynthia Wanjiku',  'cynthiawanjiku@students.zetech.ac.ke','0745678901'),
('DIT-03-0089/2026', 'David Kiprop',     'davidkiprop@students.zetech.ac.ke',  '0756789012'),
('DIT-03-0090/2026', 'Faith Njeri',      'faithnjeri@students.zetech.ac.ke',   '0767890123'),
('DIT-03-0091/2026', 'George Omondi',    'georgeomondi@students.zetech.ac.ke', '0778901234'),
('DIT-03-0092/2026', 'Hellen Chebet',    'hellenchebet@students.zetech.ac.ke', '0789012345'),
('DIT-03-0093/2026', 'Ian Kamau',        'iankamau@students.zetech.ac.ke',     '0790123456');

-- 2. ADMINS: the Dean's office. Separate login from students.
--    (The first admin is created by app.py with a hashed password.)
CREATE TABLE admins (
    admin_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name         TEXT    NOT NULL,
    phone_number      TEXT    NOT NULL,
    department        TEXT    NOT NULL,
    registration_no   TEXT    NOT NULL UNIQUE,
    password          TEXT    NOT NULL,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. POSITIONS: the six executive positions.
CREATE TABLE positions (
    position_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    position_name TEXT    NOT NULL UNIQUE
);

INSERT INTO positions (position_name) VALUES
('President'),
('Vice President'),
('Finance'),
('Secretary General'),
('Academics Secretary'),
('Sports & Entertainment Secretary');

-- 4. ELECTIONS: controls start / pause / stop.
CREATE TABLE elections (
    election_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT    NOT NULL,
    start_time    TIMESTAMP,
    end_time      TIMESTAMP,
    status        TEXT    NOT NULL DEFAULT 'closed'
                  CHECK (status IN ('open', 'closed', 'paused')),
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO elections (title, status) VALUES
('Zetech University Student Elections 2026', 'closed');

-- 5. CANDIDATES: students who apply to run. Pending until the admin approves.
CREATE TABLE candidates (
    candidate_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id        INTEGER NOT NULL,
    position_id       INTEGER NOT NULL,
    manifesto         TEXT,
    photo_path        TEXT,
    results_path      TEXT,
    fee_compliance    INTEGER NOT NULL DEFAULT 0
                      CHECK (fee_compliance IN (0, 1)),
    status            TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'rejected')),
    applied_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id)  REFERENCES students(student_id),
    FOREIGN KEY (position_id) REFERENCES positions(position_id),
    UNIQUE (student_id, position_id)
);

-- 6. VOTES: one vote per student per position per election.
--    The UNIQUE constraint enforces one-vote-per-voter in the database itself.
CREATE TABLE votes (
    vote_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id    INTEGER NOT NULL,
    candidate_id  INTEGER NOT NULL,
    position_id   INTEGER NOT NULL,
    election_id   INTEGER NOT NULL,
    voted_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id)   REFERENCES students(student_id),
    FOREIGN KEY (candidate_id) REFERENCES candidates(candidate_id),
    FOREIGN KEY (position_id)  REFERENCES positions(position_id),
    FOREIGN KEY (election_id)  REFERENCES elections(election_id),
    UNIQUE (student_id, position_id, election_id)
);

-- 7. AUDIT LOG: every important action is timestamped.
CREATE TABLE audit_log (
    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id    INTEGER,
    actor_role  TEXT,
    action      TEXT NOT NULL,
    details     TEXT,
    logged_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. LOGIN CODES: one-time email codes for student login verification.
--    Only a hash of the code is stored; codes expire after 5 minutes.
CREATE TABLE login_codes (
    student_id  INTEGER PRIMARY KEY,
    code_hash   TEXT    NOT NULL,
    expires_at  REAL    NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    sent_at     REAL    NOT NULL,
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);
