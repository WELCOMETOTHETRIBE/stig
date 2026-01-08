"""Railway entry point for Flask application.

Railway's Railpack auto-detects Flask apps in main.py or app.py.
This file imports the Flask app instance from web_server.py.
"""

import sys
import traceback
import os

# Print startup info
print("Starting STIG Generator application...", file=sys.stderr)
print(f"Python version: {sys.version}", file=sys.stderr)
print(f"Working directory: {os.getcwd()}", file=sys.stderr)
print(f"Python path: {sys.path}", file=sys.stderr)

try:
    print("Attempting to import web_server...", file=sys.stderr)
    from web_server import app
    print("✓ Successfully imported Flask app from web_server", file=sys.stderr)
    print(f"App type: {type(app)}", file=sys.stderr)
    print(f"App callable: {callable(app)}", file=sys.stderr)
    print(f"App name: {app.name}", file=sys.stderr)
    
    # Verify app is WSGI callable
    if not callable(app):
        raise ValueError("App is not callable - cannot be used with WSGI")
    print("✓ App is WSGI callable", file=sys.stderr)
except Exception as e:
    print(f"✗ ERROR: Failed to import Flask app: {e}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    # Create a minimal app so gunicorn doesn't crash
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    error_msg = str(e)
    error_traceback = traceback.format_exc()
    
    @app.route('/')
    def error():
        return f"""
        <html>
        <head><title>STIG Generator - Error</title></head>
        <body>
            <h1>Application Error</h1>
            <p>The application failed to start. Error details:</p>
            <pre>{error_msg}</pre>
            <h2>Full Traceback:</h2>
            <pre>{error_traceback}</pre>
        </body>
        </html>
        """, 500
    
    @app.route('/health')
    def health():
        return jsonify({
            'status': 'error', 
            'error': error_msg,
            'traceback': error_traceback
        }), 500

# Railway will automatically detect this as a Flask app
# and use gunicorn to serve it
if __name__ == '__main__':
    # This won't be used in production (gunicorn handles it)
    # But useful for local testing
    import os
    port = int(os.environ.get('PORT', 4000))
    app.run(host='0.0.0.0', port=port, debug=False)

