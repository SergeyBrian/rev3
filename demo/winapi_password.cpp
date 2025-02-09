#include <windows.h>

int main() {
    CHAR password[256];
    DWORD bytesRead;
    HANDLE hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    
    if (hStdInput == INVALID_HANDLE_VALUE || hStdOutput == INVALID_HANDLE_VALUE) {
        return 1;
    }
    
    LPCSTR prompt = "Enter password: ";
    DWORD written;
    WriteFile(hStdOutput, prompt, lstrlenA(prompt), &written, NULL);
    
    ReadFile(hStdInput, password, sizeof(password) - 1, &bytesRead, NULL);
    password[bytesRead - 2] = '\0'; // Убираем \r\n в конце ввода
    
    if (lstrcmpA(password, "p4ssw0rd") == 0) {
        LPCSTR successMsg = "Success!\n";
        WriteFile(hStdOutput, successMsg, lstrlenA(successMsg), &written, NULL);
    } else {
        LPCSTR failMsg = "Wrong password!\n";
        WriteFile(hStdOutput, failMsg, lstrlenA(failMsg), &written, NULL);
    }
    
    return 0;
}
