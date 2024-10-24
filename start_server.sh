#!/bin/bash

# Set the working directory to the directory containing this script
cd "/home/ubuntu/server/src"

# Define the port to use (this can be passed as an argument or set here)
PORT=$1

# Ensure the logs directory exists
mkdir -p /home/ubuntu/server_logs

# Start the Agario server with the specified port
node ./index.js $PORT > /home/ubuntu/server_logs/server_$PORT.log 2>&1 &

# Print a message indicating the server has started
echo "Server started on port $PORT"
