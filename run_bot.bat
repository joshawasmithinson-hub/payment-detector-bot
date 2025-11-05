@echo off
:loop
cd /d "C:\Users\adenv\Desktop\payment detection"
call "venv\Scripts\activate"
python paymentdetect.py
echo Bot crashed. Restarting in 5 seconds...
timeout /t 5
goto loop