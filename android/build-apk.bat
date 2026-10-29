@echo off
rem Cortmed Security APK'sini derler ve CortmedSecurity\dist klasorune kopyalar.
setlocal
cd /d "%~dp0"
if "%JAVA_HOME%"=="" set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
call "%~dp0gradlew.bat" :app:assembleRelease --console=plain || goto :error
if not exist "..\dist" mkdir "..\dist"
copy /y "%LOCALAPPDATA%\CortmedBuild\app\outputs\apk\release\app-release.apk" "..\dist\CortmedSecurity.apk" >nul || goto :error
echo.
echo Hazir: %~dp0..\dist\CortmedSecurity.apk
exit /b 0
:error
echo Derleme basarisiz.
exit /b 1
