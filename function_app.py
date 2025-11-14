import azure.functions as func
import logging
import os
import sqlite3
import tempfile

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="http_trigger")
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )
    
@app.route(route="health_check")
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(f"UP!")

def _seed_user_table(cursor: sqlite3.Cursor) -> None:
    """Create a trivial dataset so the vulnerable endpoint returns something."""
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            role TEXT
        )
        """
    )
    cursor.execute("INSERT OR IGNORE INTO users(username, role) VALUES ('alice', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users(username, role) VALUES ('bob', 'user')")

@app.route(route="vulnerable_user_lookup")
def vulnerable_user_lookup(req: func.HttpRequest) -> func.HttpResponse:
    """
    Intentionally vulnerable endpoint for testing SQLi detections.
    Do NOT deploy this code to production.
    """
    username = req.params.get("username", "")
    if not username:
        return func.HttpResponse("missing username", status_code=400)

    default_db = os.path.join(tempfile.gettempdir(), "users.db")
    db_path = os.getenv("USER_DB_PATH", default_db)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    _seed_user_table(cursor)

    # SQL injection vulnerability: direct string interpolation without sanitization.
    query = f"SELECT username, role FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except sqlite3.Error as exc:
        return func.HttpResponse(f"database error: {exc}", status_code=500)
    finally:
        conn.commit()
        conn.close()

    if not rows:
        return func.HttpResponse(f"No user found for '{username}'", status_code=404)

    result_lines = [f"{row[0]} ({row[1]})" for row in rows]
    return func.HttpResponse("\n".join(result_lines))
