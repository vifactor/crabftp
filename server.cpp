#include "server.h"

#include <thread>
#include <chrono>
#include <csignal>
#include <iostream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>

using namespace std::chrono_literals;

namespace {
bool done{false};
}

Server::Server() {}

void Server::serve()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "ERROR opening socket";
        return;
    }

    struct sockaddr_in serv_addr;
    memset((void *) &serv_addr, 0, sizeof(serv_addr));
    const int portno = 1025;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "ERROR on binding" << std::endl;
        return;
    }
    listen(sockfd, 5);

    while(!done) {
        // register signal SIGINT and signal handler
        signal(SIGINT, [](int signum) {
            std::cout << "Interrupt signal (" << signum << ") received.\n";
            done = true;
        });

        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            std::cerr << "ERROR on accept" << std::endl;
            continue;
        }

        // create a thread here to handle the connection
        std::thread clientThread([newsockfd]() {
            char buffer[256];
            memset(buffer, 0, sizeof(buffer));
            int n = read(newsockfd, buffer, 255);
            if (n < 0) {
                std::cerr << "ERROR reading from socket" << std::endl;
                return;
            }

            std::cout << "Here is the message: \n" << std::string_view(buffer, n);

            const std::string replyMsg{"I got your message\n"};
            n = write(newsockfd, replyMsg.data(), replyMsg.size());
            if (n < 0) {
                std::cout << "ERROR writing to socket" << std::endl;
                return;
            }
            close(newsockfd);
        });
        clientThreads.push_back(std::move(clientThread));
    }

    close(sockfd);
    for (auto& clientThread : clientThreads) {
        clientThread.join();
    }
}
