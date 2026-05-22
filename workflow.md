# Workflow

1. Install Python 3.11 or newer.
2. Create a virtual environment and install Flask.
3. Run `python app.py`.
4. Log in as admin at `/admin/login`.
5. Add sermons, devotionals, categories, events, and gallery photos.
6. Replace sample images, service times, social links, pastor details, and donation information.
7. Set a secure `SECRET_KEY` environment variable before publishing.

Recommended editing order:

1. Update ministry information in `templates/base.html`, `templates/about.html`, and `templates/home.html`.
2. Replace sample leaders and pastor profile.
3. Add real categories and sermon content from the admin dashboard.
4. Configure deployment using `README.md`.
