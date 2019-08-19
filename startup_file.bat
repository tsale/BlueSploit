@echo off
set /p Input=""
echo The User is: %Input%
echo  ========================================================================================================
echo.
echo.
echo.
echo.

dir /a "%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
echo  ========================================================================================================

echo.
echo.
echo.
echo.
echo.

dir /a "%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup"
echo  ========================================================================================================

echo.
echo.
echo.
echo.
echo 
dir /a "C:\Users\%Input%\Start Menu\Programs\Startup"
echo ========================================================================================================

echo.
echo.
echo.
echo.


dir /a "%ProgramFiles%\Startup\"
echo  ========================================================================================================

echo.
echo.
echo.
echo.

dir /a "C:\Windows\Start Menu\Programs\startup"
echo  ========================================================================================================

echo.
echo.
echo.
echo.

dir /a "C:\Users\%Input%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
echo  ========================================================================================================

echo.
echo.
echo.
echo.

dir /a "C:\%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"
echo  ========================================================================================================

echo.
echo.
echo.
echo.

dir /a "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
echo  ========================================================================================================

echo.
echo.
echo.

dir /a "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"
echo  ========================================================================================================

echo.
echo.
echo.

dir /a "%ALLUSERSPROFILE%\Start Menu\Programs\Startup"
echo  ========================================================================================================

echo.
echo.
echo.


type "C:\Windows\winstart.bat"
echo  ========================================================================================================

echo.
echo.


type "%windir%\wininit.ini"
echo  ========================================================================================================

echo.
echo.
echo.
echo.

echo Win.ini file:
echo.
type "%windir%\win.ini" 
echo  ========================================================================================================

