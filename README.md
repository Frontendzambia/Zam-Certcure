# Zam Certcure Manager

A Flask + SQLite dashboard that monitors SSL certificate expiry, renews certificates with Certbot, and sends email alerts before anything expires.

## Features

- **Dashboard:** certificate inventory with days left and status (Healthy, Warning, Critical, Expired, Check Failed), search and filters.
- **Expiry Monitoring:** every certificate sorted by time remaining, with the ones that need renewal highlighted.
- **Renewals:** renewal tasks, one-click Certbot renewal, and automation (auto-create tasks, auto-run Certbot). After a renewal the live certificate is re-checked and old and new expiry dates are recorded.
- **Notifications & Alerts:** email reminders at configurable days (default 30, 14, 7, 3, 1), alerts for expired certificates and failed checks, test email, and a send history.
- **Scan Domain:** inspect any domain's certificate (issuer, names covered, dates, key, TLS version) and check whether browsers would trust it, then add it to monitoring.
- **Import Certificate:** track certificate files (`.pem`, `.crt`, `.cer`, DER) by their dates. Files containing a private key are rejected.
- **Reports:** certificate status, expiring certificates, expired and failed checks, and renewal history. Export as CSV or print to PDF.
- **Audit Logs:** searchable record of certificate changes, imports, scans, renewals, settings, user changes and sign-ins, with CSV export.
- **Users & Permissions:** Administrator, Operator and Viewer roles, with optional custom permissions per user.
- **Settings:** thresholds, background monitoring schedule, SMTP, Certbot path, backups (create, download, restore, delete) and inactivity timeout.
- **Security:** login required, CSRF protection, automatic sign-out after inactivity (5 minutes by default), and login attempt limiting.

## Requirements

- Python 3.10 or newer
- `flask` and `cryptography`
- Certbot, only if you want to renew certificates from the dashboard

```bash
pip install flask cryptography
```

## Run

```bash
python app.py
```

This serves the app on `http://localhost:5000`. To use another port (for example 8080):

```bash
flask --app app run --port 8080
```

### First start

There are no users yet, so the login page sends you to a one-time **Create the administrator** form. After that, `/setup` closes and everyone signs in at the login screen. Add more users under **Users & Permissions**.

### Configuration

| Variable | Purpose |
| --- | --- |
| `FLASK_SECRET_KEY` | Signs login sessions. **Set a long random value before real use.** |
| `FLASK_DEBUG=1` | Development mode. Never expose it publicly. |
| `ZAM_DISABLE_SCHEDULER=1` | Turns off the background monitor in this process. |

Everything else (thresholds, SMTP, reminder days, timeouts) is set in the **Settings** and **Notifications & Alerts** popups and stored in the database.

## Using Certbot

Certbot is a separate program that must be installed on the same server as the dashboard. The dashboard runs:

```
certbot renew --cert-name <certificate name>
```

For this to work:

1. Certbot is installed and the certificate was issued by Certbot (Let's Encrypt). Certificates from other authorities can still be monitored but not renewed.
2. The **Certbot Certificate Name** in the dashboard matches `sudo certbot certificates`.
3. The app can read `/etc/letsencrypt`, which usually means running as root or with sudo.
4. The certificate is within 30 days of expiry. Certbot refuses to renew earlier.
5. Your web server reloads after renewal, for example with `--deploy-hook "systemctl reload nginx"`. Without it the dashboard marks the task **Unverified** because the live certificate did not change.

Test your setup with `sudo certbot renew --cert-name <name> --dry-run`.

## Background monitoring

Reminder emails, automatic renewal tasks, automatic Certbot runs and daily backups only happen while **background monitoring** is on (Settings > Monitoring). It re-checks all websites on the schedule you choose. If you run several worker processes, set `ZAM_DISABLE_SCHEDULER=1` on all but one.

## Roles

| Permission | Administrator | Operator | Viewer |
| --- | :-: | :-: | :-: |
| View dashboard, monitoring and renewals | Yes | Yes | Yes |
| Add, edit and delete websites; scan and import | Yes | Yes | No |
| Create tasks and run renewals | Yes | Yes | No |
| Configure and send alerts | Yes | Yes | No |
| Generate and export reports | Yes | Yes | Yes |
| View audit logs | Yes | Yes | No |
| Manage users and permissions | Yes | No | No |
| Change settings and backups | Yes | No | No |

Administrators always have every permission. Other users can be given a custom set.

## Project structure

```
app.py                  Flask app: routes, monitoring, auth, scheduler
templates/index.html    Dashboard, popup panels, login, setup and report page
static/style.css        All styles
static/panels.js        Popups, sidebar highlight and inactivity timer
ssl_dashboard.db        SQLite database (created on first run)
backups/                Database backups (created on first run)
```

## Security notes

- Keep `ssl_dashboard.db` and `backups/` private. They contain users' password hashes and the SMTP password.
- Run behind HTTPS (for example nginx or Caddy) when exposed beyond localhost.
- Imported certificates are tracked by their dates only. Never upload private keys.
- Scan Domain connects to whatever domain a user types, so only give that permission to trusted users.

## Troubleshooting

- **Forgot the only administrator's password:** delete that row from the `users` table in `ssl_dashboard.db`. The first-time setup form then appears again.
- **Email does not send:** check the SMTP settings under Settings > Integrations and use **Send test email**. The error message is shown in the popup and the send history.
- **Renewal says Failed:** the message is Certbot's own output. Run the same command in a terminal on the server to see the full detail.
- **Styles look stale after an update:** hard-refresh the browser (Ctrl+F5).
