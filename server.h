#ifndef SERVER_H
#define SERVER_H

#include <unordered_map>
#include <string>

class Server {
  public:
    Server();
    ~Server();
    void serve();

  private:
    struct Command {
        std::string cmd;
        std::string args;
    };

    struct Client {
        int port;
        // relative to server's rootPath
        std::string cwd;
    };

    // this is server state
    bool m_isDataPortBusy{false};
    enum class DataCommand {
        None,
        List,
        Repr
    } m_pendingCmd{DataCommand::None};
    int m_pendingClientSocket;

    using ClientSocket = int;

    std::unordered_map<ClientSocket, Client> m_clients;
    int m_dataPort{1026};
    int m_cmdPort{1025};

    int m_dataSocket;
    int m_cmdSocket;
  private:
    std::string makeReply(ClientSocket fd,  const Command& cmd);
    static Command parseCommand(const std::string& cmd);
};

#endif // SERVER_H
