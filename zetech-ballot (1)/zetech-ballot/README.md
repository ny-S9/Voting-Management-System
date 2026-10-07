# Zetech Electronic Ballot System

Flask + SQLite voting portal built on your 7-table schema (`schema.sql`).

## Run it
```
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000. The database (`ballot.db`) is created automatically on first run.

## Email verification (students)
After a correct password, students must enter a 6-digit code emailed to their school email (valid 5 minutes, 5 tries, resend every 30 s). Only a hash of the code is stored.

**Demo mode (default):** with no email server configured, the code is printed in the terminal and shown on the page so you can test. Do NOT use demo mode for the real election.

**Real emails (Gmail example):** turn on 2-step verification on a Gmail account, create an App Password, then set these before starting the app.
Windows (PowerShell):
```
$env:SMTP_HOST="smtp.gmail.com"; $env:SMTP_PORT="587"
$env:SMTP_USER="youraddress@gmail.com"; $env:SMTP_PASS="your-16-letter-app-password"
python app.py
```
Mac/Linux: use `export SMTP_HOST=smtp.gmail.com` (and the same for the others).

## Logins
| Who | Username | Password |
|---|---|---|
| Dean's office (admin) | `456` (registration number, tab "Dean's office") | `456` - change it under Control room > Settings |
| Students | their admission number, e.g. `DIT-03-0085/2026` | they choose one on **Activate your account** (needs the school email from the `students` table, e.g. `johnmwangi@students.zetech.ac.ke`) |

## What each role can do
- **Student / voter**: activate account, log in, read manifestos, vote once per position, watch live results.
- **Candidate** (any student): *Run for office* page saves position, manifesto, photo, results file and fee confirmation into the `candidates` table (files go in `uploads/`). Can edit while pending, sees status, follows own count on Live results.
- **Admin**: start / pause / stop the election, approve or reject candidates (fee must be verified first), add students, reset a student's password, view the audit log, download a CSV report, create a new election.

## Where things are
- `app.py` routes and logic · `schema.sql` database · `templates/` pages · `static/` CSS, logo, `img/v1.jpg`, `img/v2.jpg`
- Flow: admin opens the election only after at least one candidate is approved; applications close while voting is open.

## Security built in
- Email one-time code after the password for every student login
- Passwords hashed (scrypt); sessions expire after 15 minutes idle; CSRF token on every form
- One vote per position enforced by the database `UNIQUE (student_id, position_id, election_id)` and checked in code
- 5 wrong logins lock that account for 5 minutes
- Uploads: allowed types only, random file names; results documents visible only to the owner and admin
- Every login, vote, application and admin action goes into `audit_log` (votes are logged by position, not by candidate)

## Deploy on PythonAnywhere
Upload the folder, create a Flask web app pointing at `app.py` (`app` is the Flask object), set env `SECRET_KEY`, and make sure `ballot.db` and `uploads/` are writable.

## Good to know
- Times are stored in UTC and shown in East Africa Time.
- Because `votes` links a student to a candidate (as in your schema), anyone with database access could see who voted for whom. The web pages never show that.
