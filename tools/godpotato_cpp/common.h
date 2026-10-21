#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <objbase.h>
#include <objidl.h>
#include <oleauto.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>

void gpLog(const char* fmt, ...);
void gpLogW(const wchar_t* fmt, ...);

std::vector<uint8_t> gpBase64Decode(const std::string& text);
std::string gpWideToAnsi(const std::wstring& s);
