#include <bitset>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <pieces.hpp>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

void websocket(pieces::ipv6_tcp_server &server, pieces::ssl &ssl) {

  auto callback = [&]() {
    for (;;) {

      auto ctx = server.get_context();

      try {
        auto s = ssl.new_stream(ctx.fd);

        pieces::websocket<decltype(s)> wss(s);

        while (true) {

          bool fin = false;

          while (!fin){
            auto opt = wss.read();
            auto [str, fin] = opt.value();
            std::cout << str << std::endl;
          }

        }

      } catch (std::exception &ec) {
        std::cerr << ec.what() << std::endl;
      }
    }
  };

  for (int i = 0; i < 10; i++) {
    std::thread thrd(callback);
    thrd.detach();
  }

  callback();
}

int main() {
  try {
    pieces::ipv6_tcp_server server(4433);

    server.sync_acceptor();

    pieces::ssl ssl("/etc/ssl/localcerts/apache.pem",
                    "/etc/ssl/localcerts/apache.key");

    websocket(server, ssl);
  } catch (std::exception &ec) {
    std::cerr << ec.what() << std::endl;
  }

  return 0;
}
