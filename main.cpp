#include <iostream>
#include "server.h"


int main() {
    std::cout << "Hello World!" << std::endl;

    Server s;
    s.serve();

    return EXIT_SUCCESS;
}
