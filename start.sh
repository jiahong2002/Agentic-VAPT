#!/bin/bash
# Start the Agentic VAPT system

echo "Building all packages..."
npm run build

echo ""
echo "Starting backend on http://localhost:3001"
node packages/backend/dist/index.js &
BACKEND_PID=$!

echo "Starting frontend on http://localhost:5173"
npm run dev -w packages/frontend &
FRONTEND_PID=$!

echo ""
echo "✅ Agentic VAPT running!"
echo "   Frontend: http://localhost:5173"
echo "   Backend:  http://localhost:3001"
echo ""
echo "Press Ctrl+C to stop."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT
wait