#include "server.h"

#include <fs.h>

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
std::filesystem::path rootPath{"/lhome/vikkopp"};
}

Server::Server() {
    // register signal SIGINT and signal handler
    signal(SIGINT, [](int signum) {
        std::cout << "Interrupt signal (" << signum << ") received.\n";
        done = true;
    });
    m_currentDataPort = 1026;
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

                // here we handle the commands from clients
                std::cout << "Received data: " << buffer << std::endl;
                Command cmd = parseCommand(buffer);

                // answer the client appropriately
                auto reply = makeReply(evlist[n].data.fd, cmd);
                std::cout << "replying with " << reply << std::endl;
                ret = write(evlist[n].data.fd, reply.data(), reply.size());
                if (ret < 0) {
                    std::cerr << "ERROR writing to socket" << std::endl;
                    continue;
                }
            }
        }
    }

    close(sockfd);
}

Server::Command Server::parseCommand(const std::string& cmd) {
    Command ftpCmd;
    auto pos = cmd.find(' ');
    if (pos == std::string::npos) {
        // compensate for \r\n
        ftpCmd.cmd = cmd.substr(0, cmd.size() - 2);
    } else {
        ftpCmd.cmd = cmd.substr(0, pos);
        // compensate for \r\n
        ftpCmd.args = cmd.substr(pos + 1, cmd.size() - (pos + 1) - 2);
    }
    return ftpCmd;
}

std::string Server::makeReply(ClientSocket fd,  const Command& cmd) {

    if (cmd.cmd == "AUTH") {
        // https://www.rfc-editor.org/rfc/rfc2228
        // > If the server does recognize the AUTH command but does not implement the
        // security extensions, it should respond with reply code 502.
        return "502 Not implemented.\n";
    } else if (cmd.cmd == "USER") {
        // we do not use authentication, so we accept any user name
        return "230 User logged in, proceed.\n";
    } else if (cmd.cmd == "PASS") {
        // this command will never be called for this server because we accept all users
        return "230 Login successful.\n";
    } else if (cmd.cmd == "SYST") {
        std::cout << "cmd.cmd=" << cmd.cmd << std::endl;
        return "215 UNIX\n";
    } else if (cmd.cmd == "FEAT") {
        return "211-Features:\n"
               " UTF8\n"
               "211 End\n";
    }
    else if (cmd.cmd == "OPTS") {
        return "200 OK\n";
    } else if (cmd.cmd == "PWD") {
        // This command displays the current working directory on the server for the logged in user.
        // TODO: server has to preserve the current working directory for each user
        return "257 \"/\" is the current directory\n";
    } else if (cmd.cmd == "TYPE") {
        // TODO: keep the binary or ascii mode for each user, https://cr.yp.to/ftp/type.html#type
        return "200 Type set to I.\n";
    } else if (cmd.cmd == "PASV") {
        // Server response is a single line showing the IP address of the server and the TCP port
        // number where the server is accepting data connections. servers use the format:
        //          227 =h1,h2,h3,h4,p1,p2
        // where the server's IP address is h1.h2.h3.h4 and the TCP port number is p1*256+p2.

        // TODO: request available port from OS
        const int nextDataPort = m_currentDataPort++;
        m_clients[fd] = {nextDataPort};
        std::cout << "Client's fd: " << fd << std::endl;
        const auto p1 = nextDataPort / 256;
        const auto p2 = nextDataPort % 256;
        return "227 Entering Passive Mode (127,0,0,1," + std::to_string(p1) + "," + std::to_string(p2) + ")\n";
    } else if (cmd.cmd == "LIST") {

        //write listing to the data connection
        const auto dataport = m_clients.at(fd).port;
        std::cout << "Dataport: " << dataport << std::endl;

        sockaddr_in serv_addr;
        memset((void *) &serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(dataport);

        int datafd = socket(AF_INET, SOCK_STREAM, 0);
        if (datafd < 0) {
            std::cerr << "ERROR opening data socket";
            return "";
        }
        if (bind(datafd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            std::cerr << "ERROR on binding data socket" << std::endl;
            return "";
        }
        if (listen(datafd, 5) < 0) {
            std::cerr << "ERROR on listening data socket" << std::endl;
            return "";
        }

        std::cout << "Accepting data" << std::endl;
        sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int clidatafd = accept(datafd, (struct sockaddr *)&cli_addr, &clilen);
        if (clidatafd < 0) {
            std::cerr << "ERROR on accept" << std::endl;
            return "";
        }
        std::cout << "Data connection accepted" << std::endl;

        std::string reply = "150 Here comes the directory listing.\n";
        int ret = write(fd, reply.data(), reply.size());
        if (ret < 0) {
            std::cerr << "ERROR writing to socket" << std::endl;
            // FIXME: reply with error code
            return "";
        };

        auto listing = listDirContents(rootPath / m_clients.at(fd).cwd);

        write(clidatafd, listing.data(), listing.size());
        std::cout << "clidatafd: " << clidatafd << std::endl;
        std::cout << "datafd: " << datafd << std::endl;

        close(clidatafd);
        close(datafd);

        return "226 Directory send OK.\n";
    } else if (cmd.cmd == "CWD") {
        // This command allows the user to change the current working directory to the specified directory.
        // The new directory must be specified as a parameter.
        // The server response is a 250 status code if the directory change was successful.
        if (std::filesystem::exists(rootPath / cmd.args)) {
            m_clients[fd].cwd = cmd.args;
            return "250 Directory successfully changed.\n";
        } else {
            // If the directory does not exist or the user does not have permission to access the directory,
            // the server will return a 550 status code.
            return "550 Failed to change directory.\n";
        }
    } else if (cmd.cmd == "SIZE") {
        // This command is used to determine the size of a file on the server.
        // The server response is a 213 status code followed by the size of the file in bytes.
        // If the file does not exist or the user does not have permission to access the file,
        // the server will return a 550 status code.
        auto path = rootPath / m_clients.at(fd).cwd / cmd.args;
        if (std::filesystem::exists(path)) {
            return "213 " + std::to_string(std::filesystem::file_size(path)) + "\n";
        } else {
            return "550 File not found.\n";
        }
        // } else if (cmd.cmd == "RETR") {
        //     return "150 Opening BINARY mode data connection for file1.txt (220 bytes).\n"
        //            "226 Transfer complete.\n";
        // } else if (cmd.cmd == "STOR") {
        //     return "150 Ok to send data.\n"
        //            "226 Transfer complete.\n";
        // } else if (cmd.cmd == "NOOP") {
        //     return "200 NOOP ok.\n";
    } else if (cmd.cmd == "QUIT") {
        return "221 Goodbye.\n";
    }

           // print command byte by byte
    std::cout << "Unknown command:" << cmd.cmd << '\n';
    for (char c : cmd.cmd) {
        std::cout << (int)c << " ";
    }
    std::cout << std::endl;

    return "";
}

