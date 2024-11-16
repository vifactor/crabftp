#include <iostream>
#include "server.h"


int main() {
    std::cout << "Welcome to crabftp server!" << std::endl;

    Server s;
    s.serve();

    return EXIT_SUCCESS;
}
