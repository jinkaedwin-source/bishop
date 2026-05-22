# LIGHT INTERNATIONAL MINISTRY Website App

A beginner-friendly Christian church and ministry website built with HTML, CSS, JavaScript, Python Flask, and SQLite.

## Features

- Home page with welcome, hero scripture, mission, and vision
- Sermons with audio/video links, thumbnails, categories, comments, and search
- Daily devotionals with comments and search
- Bible studies, church events, conferences, and crusades
- Prayer requests, testimonies, newsletter subscription, gallery, contact, donation, about, pastor, and leaders pages
- User registration/login and secure admin login with hashed passwords
- Admin dashboard for sermons, devotionals, events, categories, and gallery uploads
- Responsive modern design with warm spiritual colors and smooth animations

## Project Structure

```text
bishop/
  app.py
  database.db
  sample_sermons.csv
  sample_bible_studies.csv
  workflow.md
  questions.md
  README.md
  data/
  static/
    style.css
    script.js
    uploads/
  templates/
```

## Local Setup

```powershell
cd C:\Users\hp\bishop
python -m venv .venv
.\.venv\Scripts\activate
pip install flask
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Admin Login

Default admin account:

- Email: `admin@lightministry.local`
- Password: `Admin123!`

Change this password before using the project publicly.

## Netlify Compatibility

Netlify hosts static frontends by default. This project includes a Flask backend and SQLite database, so deploy the Flask app to a Python host such as Render, Railway, Fly.io, or PythonAnywhere. You can still use Netlify for a static landing frontend and connect it to the hosted Flask backend.

For a full Flask deployment, use a Python-capable host and set:

```text
SECRET_KEY=replace-with-a-long-random-secret
```

## Customization

- Update church details in `templates/base.html`.
- Update mission and vision in `templates/home.html`.
- Replace pastor and leader information in `templates/pastor.html` and `templates/leaders.html`.
- Add real sermons, devotionals, events, categories, and gallery images through `/admin`.
- Replace placeholder donation instructions in `templates/donate.html`.

## Security Notes

- Passwords are hashed with Werkzeug.
- Admin routes require authenticated admin sessions.
- File uploads are restricted by extension.
- Set a strong `SECRET_KEY` in production.
- Add HTTPS, backups, CSRF protection, and a real email provider before public launch.
