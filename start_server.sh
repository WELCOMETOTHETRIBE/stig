#!/bin/bash
# Start STIG Generator Web Server

cd "$(dirname "$0")"

# Check if server is already running
if [ -f server.pid ]; then
    OLD_PID=$(cat server.pid)
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "Server is already running (PID: $OLD_PID)"
        echo "Access it at: http://localhost:4000"
        exit 0
    else
        echo "Removing stale PID file..."
        rm -f server.pid
    fi
fi

# Check if port 4000 is in use
if lsof -ti:4000 > /dev/null 2>&1; then
    echo "Error: Port 4000 is already in use"
    echo "Please stop the existing process or use a different port"
    exit 1
fi

# Start the server
echo "Starting STIG Generator Web Server..."
echo "Server will be available at: http://localhost:4000"

# Use venv if it exists
if [ -d venv ]; then
    source venv/bin/activate
    python web_server.py &
else
    python3 web_server.py &
fi
SERVER_PID=$!

# Save PID
echo $SERVER_PID > server.pid
echo "Server started with PID: $SERVER_PID"
echo "To stop the server, run: kill $SERVER_PID"
echo "Or use: pkill -f web_server.py"


