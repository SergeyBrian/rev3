#include <windows.h>

const CHAR real_password[] = "\x52\x16\x51\x51\x55\x12\x50\x46";

int main() {
    CHAR password[256];
    DWORD bytesRead;
    HANDLE hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);

    if (hStdInput == INVALID_HANDLE_VALUE ||
        hStdOutput == INVALID_HANDLE_VALUE) {
        return 1;
    }

    LPCSTR prompt = "Enter password: ";
    DWORD written;
    WriteFile(hStdOutput, prompt, lstrlenA(prompt), &written, NULL);

    ReadFile(hStdInput, password, sizeof(password) - 1, &bytesRead, NULL);
    password[bytesRead - 2] = '\0';

    CHAR password_decrypted[9] = "";
    for (int i = 0; i < sizeof(real_password); i++) {
        password_decrypted[i] = real_password[i] ^ 0x22;
    }

    WriteFile(hStdOutput, password_decrypted, lstrlenA(real_password), &written,
              NULL);

    if (lstrcmpA(password, password_decrypted) == 0) {
        LPCSTR successMsg = "Success!\n";
        WriteFile(hStdOutput, successMsg, lstrlenA(successMsg), &written, NULL);
    } else {
        LPCSTR failMsg = "Wrong password!\n";
        WriteFile(hStdOutput, failMsg, lstrlenA(failMsg), &written, NULL);
    }

    return 0;
}
