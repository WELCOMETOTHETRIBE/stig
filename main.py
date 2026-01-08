"""Railway entry point for Flask application.

Railway's Railpack auto-detects Flask apps in main.py or app.py.
This file imports the Flask app instance from web_server.py.
"""

import sys
import traceback

try:
    from web_server import app
    print("✓ Successfully imported Flask app from web_server", file=sys.stderr)
except Exception as e:
    print(f"✗ ERROR: Failed to import Flask app: {e}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    # Create a minimal app so gunicorn doesn't crash
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return f"Error loading application: {str(e)}", 500
    
    @app.route('/health')
    def health():
        return {'status': 'error', 'error': str(e)}, 500

# Railway will automatically detect this as a Flask app
# and use gunicorn to serve it
if __name__ == '__main__':
    # This won't be used in production (gunicorn handles it)
    # But useful for local testing
    import os
    port = int(os.environ.get('PORT', 4000))
    app.run(host='0.0.0.0', port=port, debug=False)

