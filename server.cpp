#include "server.h"

#include <thread>
#include <chrono>
#include <csignal>
#include <iostream>
#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>

using namespace std::chrono_literals;

namespace {
bool done{false};
}

Server::Server() {
    // register signal SIGINT and signal handler
    signal(SIGINT, [](int signum) {
        std::cout << "Interrupt signal (" << signum << ") received.\n";
        done = true;
    });
}

void Server::serve()
{
    // TODO: --- this can go to the constructor ---
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "ERROR opening socket";
        return;
    }

    sockaddr_in serv_addr;
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
    // ------------------------------------------

    int epfd = epoll_create1(0);
    if (0 > epfd) { perror("epoll_create1"); exit(1); }

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = STDIN_FILENO; // for quit
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);
    if (0 > ret) {
        perror("epoll_ctl");
        return;
    }

    ev.data.fd = sockfd;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    if (0 > ret) {
        perror("epoll_ctl");
        return;
    }

    constexpr int MAX = 10;
    epoll_event evlist[MAX];

    while(!done) {
        int nfds = epoll_wait(epfd, evlist, MAX, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            break;
        }

        std::cout << "nfds: " << nfds << std::endl;
        for (int n = 0; n < nfds; ++n) {
            if (evlist[n].data.fd == STDIN_FILENO) {
                char buf[256] = {0};
                fgets(buf, sizeof(buf) - 1, stdin);
                std::cout << "Some input received: " << buf << std::endl;
            } else if (evlist[n].data.fd == sockfd) {

                std::cout << "New connection" << std::endl;
                struct sockaddr_in cli_addr;
                socklen_t clilen = sizeof(cli_addr);
                int newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
                if (newsockfd < 0) {
                    std::cerr << "ERROR on accept" << std::endl;
                    continue;
                }

                // greet the ftp client
                const std::string msg = "220 Welcome to the crabftp-Server\n";
                ret = write(newsockfd, msg.data(), msg.size());
                if (ret < 0) {
                    std::cerr << "ERROR writing to socket" << std::endl;
                    continue;
                }

                // add the client socket to the epoll monitoring list
                ev.events = EPOLLIN;
                ev.data.fd = newsockfd;
                ret = epoll_ctl(epfd, EPOLL_CTL_ADD, newsockfd, &ev);
                if (ret == -1) {
                    perror("epoll_ctl");
                    break;
                }
            } else {
                // FIXME: message can be larger than 256 bytes
                char buffer[256] = {0};
                ret = read(evlist[n].data.fd, buffer, 255);
                if (ret < 0) {
                    std::cerr << "ERROR reading from socket" << std::endl;
                    continue;
                } else if (ret == 0) {
                    std::cout << "Connection closed" << std::endl;
                    close(evlist[n].data.fd);
                    continue;
                }

                // TODO: here we handle the commands from clients
                std::cout << "Received data:" <<  buffer << std::endl;
            }
        }
    }

    close(sockfd);
}
