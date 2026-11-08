#include <windows.h>
#include <winhttp.h>

/* Benign validation probe: one monitored file write, then one HTTPS POST that must pass DNS, redirection
   and TLS interception in the simulated internet, with certificate validation left on. */
static int https_post(void) {
    static const char body[] = "stealerforge-validation-body";
    DWORD status = 0, size = sizeof(status);
    int result = 3;
    HINTERNET session = WinHttpOpen(L"StealerForgeProbe/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    HINTERNET connect = session ? WinHttpConnect(session, L"validation.stealerforge-lab.net", 443, 0) : NULL;
    HINTERNET request = connect ? WinHttpOpenRequest(connect, L"POST", L"/probe", NULL, NULL, NULL,
                                                     WINHTTP_FLAG_SECURE) : NULL;
    if (request && WinHttpSendRequest(request, L"Content-Type: text/plain\r\n", (DWORD)-1L, (LPVOID)body,
                                      sizeof(body) - 1, sizeof(body) - 1, 0)
        && WinHttpReceiveResponse(request, NULL)
        && WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) {
        result = status == 200 ? 0 : 4;
    }
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    if (session) WinHttpCloseHandle(session);
    return result;
}

int main(void) {
    const char value[] = "StealerForge benign instrumentation probe\r\n";
    DWORD written = 0;
    HANDLE file = CreateFileW(L"C:\\StealerForge\\canary.txt", GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 1;
    BOOL ok = WriteFile(file, value, sizeof(value)-1, &written, NULL);
    CloseHandle(file);
    if (!ok) return 2;
    return https_post();
}
