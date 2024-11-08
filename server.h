#ifndef SERVER_H
#define SERVER_H

#include <unordered_map>
#include <string>

class Server {
  public:
    Server();
    void serve();

  private:
    struct Command {
        std::string cmd;
        std::string args;
    };

    struct Client {
        int port;
    };
    using ClientSocket = int;

    std::unordered_map<ClientSocket, Client> m_clients;
    int m_currentDataPort;
  private:
    std::string makeReply(ClientSocket fd,  const Command& cmd);
    void handleListCmd();
    static Command parseCommand(const std::string& cmd);
};

#endif // SERVER_H
