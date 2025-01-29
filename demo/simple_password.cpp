#include <iostream>

int main() {
    std::cout << "Enter password: ";
    std::string password;
    std::cin >> password;
    if (password == "p4ssw0rd") {
        std::cout << "Success!\n";
    } else {
        std::cout << "Wrong password!\n";
    }

    return 0;
}
