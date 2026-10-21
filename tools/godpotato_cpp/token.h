#pragma once

#include "common.h"

// Searches every process token (handle table walk, like SharpToken's
// ListProcessTokens) and returns a duplicated primary SYSTEM token, or nullptr.
HANDLE FindSystemToken(HANDLE hintToken);

// Returns a duplicated primary SYSTEM token when `token` already is one.
HANDLE DuplicateSystemTokenAsPrimary(HANDLE token);

bool TokenIsSystem(HANDLE token);

bool TokenGetImpersonationLevel(HANDLE token, SECURITY_IMPERSONATION_LEVEL& level);

bool TokenUserName(HANDLE token, std::wstring& name);

// Runs cmdLine with the given token and streams the child's stdout/stderr to
// this process's stdout.
void CreateProcessReadOut(HANDLE token, const std::wstring& cmdLine);

// Last-resort fallback used when the current account cannot start a process
// with the stolen token: lets the Task Scheduler service (SYSTEM) run it.
bool RunAsSystemViaTask(const std::wstring& cmdLine);
