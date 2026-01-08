"""Railway entry point for Flask application.

This file allows Railway's Railpack to auto-detect the Flask application.
It imports the Flask app instance from web_server.py.
"""

from web_server import app

# Railway will automatically detect this as a Flask app
# and use gunicorn to serve it
if __name__ == '__main__':
    # This won't be used in production (gunicorn handles it)
    # But useful for local testing
    import os
    port = int(os.environ.get('PORT', 4000))
    app.run(host='0.0.0.0', port=port, debug=False)

