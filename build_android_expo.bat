@echo off
setlocal EnableExtensions

cd /d "%~dp0"

set "DEFAULT_EXPO_DIR=expo"
set "EXPO_PROJECT_DIR=%~1"
set "BUILD_PROFILE=%~2"
set "BUILD_MODE=%~3"

if "%EXPO_PROJECT_DIR%"=="" (
    if exist "%DEFAULT_EXPO_DIR%\package.json" (
        set "EXPO_PROJECT_DIR=%DEFAULT_EXPO_DIR%"
    ) else (
        set "EXPO_PROJECT_DIR=."
    )
)

if "%BUILD_PROFILE%"=="" set "BUILD_PROFILE=production"

echo.
echo === GreyNOC Android Expo build ===
echo Expo project: %EXPO_PROJECT_DIR%
echo EAS profile:  %BUILD_PROFILE%
if /i "%BUILD_MODE%"=="local" (
    echo Build mode:    local
) else (
    echo Build mode:    Expo EAS cloud
)
echo.

if not exist "%EXPO_PROJECT_DIR%" (
    echo [ERROR] Expo project folder was not found: %EXPO_PROJECT_DIR%
    echo.
    echo Usage:
    echo   build_android_expo.bat [expo-project-dir] [eas-profile] [cloud^|local]
    echo.
    echo Examples:
    echo   build_android_expo.bat expo preview
    echo   build_android_expo.bat mobile production
    echo   build_android_expo.bat expo preview local
    exit /b 1
)

if not exist "%EXPO_PROJECT_DIR%\package.json" (
    echo [ERROR] No package.json found in %EXPO_PROJECT_DIR%.
    echo.
    echo This repository currently contains the Python desktop app. Expo builds require
    echo a React Native/Expo app folder, for example:
    echo   npx create-expo-app expo
    echo.
    echo Then rerun:
    echo   build_android_expo.bat expo preview
    exit /b 1
)

if not exist "%EXPO_PROJECT_DIR%\app.json" if not exist "%EXPO_PROJECT_DIR%\app.config.js" if not exist "%EXPO_PROJECT_DIR%\app.config.ts" (
    echo [ERROR] No Expo app config found in %EXPO_PROJECT_DIR%.
    echo Expected app.json, app.config.js, or app.config.ts.
    exit /b 1
)

where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js was not found on PATH.
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] npm was not found on PATH.
    exit /b 1
)

pushd "%EXPO_PROJECT_DIR%"
if errorlevel 1 exit /b 1

if not exist "node_modules" (
    echo Installing JavaScript dependencies...
    if exist "package-lock.json" (
        call npm ci
    ) else (
        call npm install
    )
    if errorlevel 1 (
        popd
        exit /b 1
    )
)

echo.
echo Checking Expo project health...
call npx expo-doctor
if errorlevel 1 (
    echo.
    echo [ERROR] expo-doctor reported issues. Fix those before building Android.
    popd
    exit /b 1
)

echo.
if /i "%BUILD_MODE%"=="local" (
    echo Starting local Android EAS build...
    call npx eas-cli build --platform android --profile "%BUILD_PROFILE%" --local
) else (
    echo Starting Expo EAS Android build...
    call npx eas-cli build --platform android --profile "%BUILD_PROFILE%"
)

set "BUILD_EXIT=%ERRORLEVEL%"
popd

if not "%BUILD_EXIT%"=="0" (
    echo.
    echo [ERROR] Android build failed with exit code %BUILD_EXIT%.
    exit /b %BUILD_EXIT%
)

echo.
echo Android build complete.
endlocal
