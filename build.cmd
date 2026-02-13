@echo off
setlocal

echo ============================================
echo   BurpDump - Burp Suite Extension Builder
echo ============================================
echo.

set "ROOT=%~dp0"
set "BUILD=%ROOT%build"
set "SRC=%ROOT%src"
set "API=%ROOT%api"
set "JAR=%BUILD%\BurpDump.jar"

rem ---- Optional version parameter (default: dev) ----
set "VER=%~1"
if "%VER%"=="" set "VER=dev"

rem ---- Build date ----
for /f "tokens=*" %%d in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"') do set "BUILD_DATE=%%d"

rem ---- Clean previous build ----
if exist "%BUILD%" rd /s /q "%BUILD%"
mkdir "%BUILD%"

rem ---- Generate build-info.properties (bundled into JAR) ----
mkdir "%BUILD%\burp" 2>nul
(
    echo version=%VER%
    echo build.date=%BUILD_DATE%
) > "%BUILD%\burp\build-info.properties"

rem ---- Generate MANIFEST.MF ----
(
    echo Manifest-Version: 1.0
    echo Implementation-Title: BurpDump
    echo Implementation-Version: %VER%
    echo Built-Date: %BUILD_DATE%
) > "%BUILD%\MANIFEST.MF"

rem ---- Collect all .java source files ----
set "SOURCES=%BUILD%\sources.txt"
dir /s /b "%API%\*.java" "%SRC%\*.java" > "%SOURCES%"

rem ---- Compile ----
echo Compiling (version %VER%, date %BUILD_DATE%)...
javac -d "%BUILD%" -sourcepath "%API%;%SRC%" @"%SOURCES%"
if errorlevel 1 (
    echo.
    echo [ERROR] Compilation failed.
    exit /b 1
)
del "%SOURCES%"

rem ---- Remove API interface stubs (Burp provides them at runtime) ----
del "%BUILD%\burp\I*.class" 2>nul
if exist "%BUILD%\burp\api" rd /s /q "%BUILD%\burp\api"

rem ---- Package extension classes + build-info into JAR ----
echo Packaging...
jar cfm "%JAR%" "%BUILD%\MANIFEST.MF" -C "%BUILD%" burp
if errorlevel 1 (
    echo.
    echo [ERROR] JAR creation failed.
    exit /b 1
)

rem ---- Cleanup temp files (keep JAR) ----
del /q "%BUILD%\burp\*.class" 2>nul
del /q "%BUILD%\burp\*.properties" 2>nul
rd "%BUILD%\burp" 2>nul
del "%BUILD%\MANIFEST.MF" 2>nul

echo.
echo [OK] Build successful: %JAR%
echo      Load this JAR in Burp Suite -^> Extender -^> Extensions -^> Add.
