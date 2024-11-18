#include "server.h"

#include <fs.h>

#include <thread>
#include <chrono>
#include <csignal>
#include <iostream>
#include <cstring>
#include <fstream>
#include <optional>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

using namespace std::chrono_literals;

namespace {
bool done{false};
std::filesystem::path rootPath{"/lhome/vikkopp"};

std::optional<int> makeSocket(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    // TODO: should fd be closed on failure?
    if (fd < 0) {
        std::cerr << "ERROR opening socket";
        return std::nullopt;
    }

    sockaddr_in servAddr;
    memset((void *) &servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = INADDR_ANY;
    servAddr.sin_port = htons(port);

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt))<0)
    {
        perror("setsockopt");
        return std::nullopt;
    };

    if (bind(fd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        perror("ERROR on binding socket");
        return std::nullopt;
    }
    if (listen(fd, 5) < 0) {
        perror("ERROR on listening socket");
        return std::nullopt;
    }

    return fd;
}

std::filesystem::path makeServerPath(std::string& subpath) {
    if (subpath == "/") {
        return rootPath;
    } else {
        return rootPath / subpath.substr(1);
    }
}

void logPeer(int sockfd) {
    socklen_t len;
    struct sockaddr_storage addr;
    char ipstr[INET6_ADDRSTRLEN];
    int port;

    len = sizeof addr;
    getpeername(sockfd, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        port = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        port = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
    }

    std::cout << "Peer IP address: " << ipstr << std::endl;
    std::cout << "Peer port      : " << port << std::endl;;
}
}

Server::Server() {
    // register signal SIGINT and signal handler
    signal(SIGINT, [](int signum) {
        std::cout << "Interrupt signal (" << signum << ") received.\n";
        done = true;
    });

    if (const auto socket = makeSocket(m_cmdPort); socket.has_value()) {
        m_cmdSocket = *socket;
    } else {
        throw std::runtime_error("Failed to create command socket");
    }

    if (const auto socket = makeSocket(m_dataPort); socket.has_value()) {
        m_dataSocket = *socket;
    } else {
        throw std::runtime_error("Failed to create data socket");
    }
}

Server::~Server()
{
    close(m_cmdSocket);
    close(m_dataSocket);
}

void Server::serve()
{
    int epfd = epoll_create1(0);
    if (0 > epfd) {
        perror("epoll_create1");
        return;
    }

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = STDIN_FILENO; // for quit
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);
    if (0 > ret) {
        perror("epoll_ctl");
        return;
    }

    ev.data.fd = m_cmdSocket;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, m_cmdSocket, &ev);
    if (0 > ret) {
        perror("epoll_ctl");
        return;
    }

    ev.data.fd = m_dataSocket;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, m_dataSocket, &ev);
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

        for (int n = 0; n < nfds; ++n) {
            if (evlist[n].data.fd == STDIN_FILENO) {
                char buf[256] = {0};
                fgets(buf, sizeof(buf) - 1, stdin);
                std::cout << "Some input received: " << buf << std::endl;
            } else if (evlist[n].data.fd == m_cmdSocket) {

                std::cout << "New cmd connection" << std::endl;
                struct sockaddr_in cli_addr;
                socklen_t clilen = sizeof(cli_addr);
                int newsockfd = accept(m_cmdSocket, (struct sockaddr *)&cli_addr, &clilen);
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
            } else if (evlist[n].data.fd == m_dataSocket) {
                std::cout << "New data connection" << std::endl;
                struct sockaddr_in cli_addr;
                socklen_t clilen = sizeof(cli_addr);
                int newsockfd = accept(m_dataSocket, (struct sockaddr *)&cli_addr, &clilen);
                if (newsockfd < 0) {
                    std::cerr << "ERROR on accept" << std::endl;
                    continue;
                }
                ::logPeer(newsockfd);

                // TODO: here the data connection should be handled, e.g. list files in a directory
                close(newsockfd);
            } else {
                ::logPeer(evlist[n].data.fd);
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

    std::cout << "Received cmd: " << cmd.cmd << "(" << cmd.args << ")" << " on fd: " << fd << std::endl;
    if (m_clients.contains(fd)) {
        const auto& client = m_clients[fd];
        std::cout << "Client port: " << client.port << " Client cwd: " << client.cwd << std::endl;
    } else {
        std::cout << "New client" << std::endl;
    }

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
        auto cwd = m_clients.contains(fd) ? m_clients[fd].cwd : "/";
        return "257 " + cwd + " is the current directory\n";
    } else if (cmd.cmd == "TYPE") {
        // TODO: keep the binary or ascii mode for each user, https://cr.yp.to/ftp/type.html#type
        return "200 Type set to I.\n";
    } else if (cmd.cmd == "PASV") {
        // Server response is a single line showing the IP address of the server and the TCP port
        // number where the server is accepting data connections. servers use the format:
        //          227 =h1,h2,h3,h4,p1,p2
        // where the server's IP address is h1.h2.h3.h4 and the TCP port number is p1*256+p2.

        if (!m_clients.contains(fd)) {
            m_clients[fd] = {m_dataPort, "/"};
        }

        auto dataPort = m_clients[fd].port;
        std::cout << "Client's fd: " << fd << " port: " << dataPort << std::endl;
        const auto p1 = dataPort / 256;
        const auto p2 = dataPort % 256;

        return "227 Entering Passive Mode (127,0,0,1," + std::to_string(p1) + "," + std::to_string(p2) + ")\n";
    } else if (cmd.cmd == "LIST") {
        //write listing to the data connection
        return "150 Here comes the directory listing.\n";
    } else if (cmd.cmd == "CWD") {
        // This command allows the user to change the current working directory to the specified directory.
        // The new directory must be specified as a parameter.
        // The server response is a 250 status code if the directory change was successful.
        if (!m_clients.contains(fd)) {
            m_clients[fd] = {m_dataPort, "/"}; // default directory is root
        }

        if (auto path = ::makeServerPath(m_clients[fd].cwd) / cmd.args; std::filesystem::exists(path)) {
            // FIXME: for the case of "." and ".."
            auto& cwd = m_clients[fd].cwd;
            auto appender = cwd.ends_with("/") ? cmd.args : "/" + cmd.args;
            cwd += appender;
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
        auto path = ::makeServerPath(m_clients.at(fd).cwd) / cmd.args;
        if (std::filesystem::exists(path)) {
            return "213 " + std::to_string(std::filesystem::file_size(path)) + "\n";
        } else {
            return "550 File not found.\n";
        }
    } else if (cmd.cmd == "RETR") {
        //write listing to the data connection
        return "150 Ok to send data.\n";
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

