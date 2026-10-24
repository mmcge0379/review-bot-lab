"""Local file logging for the target app.

Writes one line per HTTP request, plus named security events, to a
rotating log file on the machine the app runs on. Standard library only,
so it adds no dependency.

The file is named applog.py, not logging.py, so it does not shadow the
standard library logging module.

Wire it into app.py with two lines, after `app = Flask(__name__)`:

    import applog
    applog.init_app(app)

Then record security events where they happen, for example in login():

    applog.security_event("login_failed", username=payload.get("username", ""))
    applog.security_event("login_ok", username=user["username"])

Never pass a password, token, session cookie, or secret key as a field.

Where the log goes:
    target-app/logs/app.log by default.
    Set TARGET_APP_LOG_DIR to write somewhere else.
    The file rotates at 1 MB and keeps 5 old copies (app.log.1 to app.log.5).
"""

import logging
import os
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import has_request_context, request, session

DEFAULT_LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE_NAME = "app.log"
MAX_BYTES = 1_000_000
BACKUP_COUNT = 5
MAX_FIELD_LENGTH = 200

LOGGER_NAME = "target_app"
logger = logging.getLogger(LOGGER_NAME)


def log_dir():
    """The folder the log file is written to."""
    configured = os.environ.get("TARGET_APP_LOG_DIR")
    return Path(configured) if configured else DEFAULT_LOG_DIR


def _clean(value, limit=MAX_FIELD_LENGTH):
    """Make a value safe to write on a single log line.

    Request data is attacker controlled. A carriage return or line feed in
    a username or query string would otherwise start a new, forged log
    line (log injection). Every non-printable character, including CR and
    LF, becomes '?', and long values are cut short.
    """
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    if len(text) > limit:
        text = text[:limit] + "...(truncated)"
    return text


def configure(directory=None, level=logging.INFO):
    """Attach a rotating file handler to the app logger.

    Safe to call more than once: it adds the handler only the first time.
    Returns the path of the log file.
    """
    target_dir = Path(directory) if directory else log_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    log_path = target_dir / LOG_FILE_NAME

    for handler in logger.handlers:
        if getattr(handler, "_applog", False):
            return log_path

    handler = RotatingFileHandler(
        log_path,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    formatter = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime  # UTC timestamps, marked with Z
    handler.setFormatter(formatter)
    handler._applog = True

    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False  # keep these lines out of the console log
    return log_path


def _context():
    """Who and where, for the current request. Dashes outside a request."""
    if not has_request_context():
        return {"user": "-", "ip": "-"}
    return {
        "user": _clean(session.get("user_id", "-")),
        "ip": _clean(request.remote_addr or "-"),
    }


def _fields(fields):
    """Render keyword fields as sorted key=value pairs."""
    return " ".join(
        "%s=%s" % (_clean(key, 50), _clean(value)) for key, value in sorted(fields.items())
    )


def security_event(event, level=logging.WARNING, **fields):
    """Record a security relevant event, such as a failed login.

    event  short name, for example "login_failed" or "access_denied"
    fields extra key=value details. Never a password or secret.
    """
    context = _context()
    message = "security event=%s user=%s ip=%s" % (
        _clean(event, 50),
        context["user"],
        context["ip"],
    )
    extra = _fields(fields)
    if extra:
        message += " " + extra
    logger.log(level, message)


def info(message, **fields):
    """Record an ordinary application event."""
    context = _context()
    line = "app msg=%s user=%s ip=%s" % (_clean(message), context["user"], context["ip"])
    extra = _fields(fields)
    if extra:
        line += " " + extra
    logger.info(line)


def init_app(app, directory=None, level=logging.INFO):
    """Turn on file logging for a Flask app.

    Logs one line per request: method, path, query string, status code,
    the logged in user id, and the client address. Request bodies are not
    logged, because the login body carries the password.
    """
    log_path = configure(directory, level)

    @app.after_request
    def _log_request(response):
        context = _context()
        query = request.query_string.decode("utf-8", errors="replace")
        logger.info(
            "request method=%s path=%s query=%s status=%s user=%s ip=%s",
            _clean(request.method, 10),
            _clean(request.path),
            _clean(query) if query else "-",
            response.status_code,
            context["user"],
            context["ip"],
        )
        return response

    info("logging started", file=log_path)
    return app
