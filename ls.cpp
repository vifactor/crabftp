#include <fs.h>

#include <cstdlib>
#include <iostream>

int main() {
    std::cout << listDirContents("/lhome/vikkopp") << std::endl;
    return EXIT_SUCCESS;
}
