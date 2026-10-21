@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /std:c++17 /EHsc /O2 /MT /W3 /utf-8 /DUNICODE /D_UNICODE ^
    common.cpp objref.cpp istream.cpp ctx.cpp token.cpp trigger.cpp main.cpp ^
    /Fe:godpotato_cpp.exe ^
    /link ole32.lib oleaut32.lib advapi32.lib user32.lib psapi.lib
