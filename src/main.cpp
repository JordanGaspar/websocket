/*! Pieces library */

/*!
Author: Jordan Gaspar Alves Silva.
Year: 2023
E-mail: jordangaspar@gmail.com

MIT License

Copyright (c) 2023 Jordan Gaspar Alves Silva

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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

        while (wss.connection_alive()) {
          auto opt = wss.read();
          if (opt.has_value()) {
            std::cout << "Received: " << opt.value() << std::endl;
          }
        }

        if (!wss.connection_alive()) {
          std::cout << "connection close" << std::endl;
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
