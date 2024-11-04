#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>

using namespace std::chrono_literals;

bool done = false;

// handle Ctrl-C signal
void signalHandler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    done = true;
}

int main() {
    std::cout << "Hello World!" << std::endl;

    while(!done) {
        // register signal SIGINT and signal handler
        signal(SIGINT, signalHandler);
        std::this_thread::sleep_for(100ms);
    }
    return EXIT_SUCCESS;
}
