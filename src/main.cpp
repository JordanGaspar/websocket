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

	struct internal_t{
		pieces::ipv6_tcp_server::context_t context;
		std::string buffer;
	};

  auto callback = [&]() {
    std::queue<std::pair<pieces::ipv6_tcp_server::context_t, std::string>>
        internal_queue;

    for (;;) {

      if (internal_queue.empty()) {
        auto ctx = server.get_context();
		internal_queue.emplace({ctx, })
      }

      try {
        auto s = ssl.new_stream(ctx.fd);

        pieces::websocket<decltype(s)> wss(s);

        while (true) {
          std::string buffer(8192, 0);
          s.read(&buffer);

          // wss.read(reinterpret_cast<uint8_t*>(buffer.data()), buffer.size());
        }
      } catch (std::exception &ec) {
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
  /*
  blocks on queue is optional
  there are queue nonblocking
  blocks to get on queue
  blocks to poll
  */
  try {
    pieces::ipv6_tcp_server server(443);

    server.sync_acceptor();

    pieces::ssl ssl("/etc/ssl/localcerts/apache.pem",
                    "/etc/ssl/localcerts/apache.key");

    websocket(server, ssl);
  } catch (std::exception &ec) {
  }

  return 0;
}
