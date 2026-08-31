@echo off
echo Starting SOVA-WAF services...

echo [1/3] Starting Test App on :8080...
start "SOVA Test App" cmd /k "cd /d %~dp0 && .venv\Scripts\python -m test_app.main"
timeout /t 2 /nobreak >nul

echo [2/3] Starting SOVA Gateway on :8443...
start "SOVA Gateway" cmd /k "cd /d %~dp0 && .venv\Scripts\python -m app.gateway.proxy"
timeout /t 2 /nobreak >nul

echo [3/3] Starting React Frontend on :5173...
start "SOVA Frontend" cmd /k "cd /d %~dp0\frontend && npm run dev"

echo.
echo All services started!
echo   Test App:   http://127.0.0.1:8080
echo   Gateway:    http://127.0.0.1:8443
echo   Dashboard:  http://localhost:5173
echo   WebSocket:  ws://127.0.0.1:8443/ws
echo.
timeout /t 5 /nobreak >nul
