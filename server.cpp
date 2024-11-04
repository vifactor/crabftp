#include "server.h"

#include <thread>
#include <chrono>
#include <csignal>
#include <iostream>

using namespace std::chrono_literals;

namespace {
bool done{false};
}

Server::Server() {}

void Server::serve()
{
    while(!done) {
        // register signal SIGINT and signal handler
        signal(SIGINT, [](int signum) {
            std::cout << "Interrupt signal (" << signum << ") received.\n";
            done = true;
        });
        std::this_thread::sleep_for(100ms);
    }
}
