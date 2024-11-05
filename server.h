#ifndef SERVER_H
#define SERVER_H

#include <thread>
#include <vector>

class Server
{
public:
    Server();
    void serve();

private:
    std::vector<std::thread> clientThreads;
};

#endif // SERVER_H
