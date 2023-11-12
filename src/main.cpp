/*MIT License

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

Author: Jordan Gaspar Alves Silva.
Year: 2023
E-mail: jordangaspar@gmail.com
Library name: pieces.
*/

#include <bitset>
#include <chrono>
#include <csignal>
#include <cstdlib>
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

void client(pieces::ssl::stream &&s) {
  try {

    pieces::websocket<decltype(s)> wss(s);

    while (wss.connection_alive()) {
      auto opt = wss.read();
      if (opt.has_value()) {
        std::cout << "Received: " << opt.value() << std::endl;
      }
    }

  } catch (std::exception &ec) {
    std::cerr << ec.what() << std::endl;
  }
}

void websocket(std::shared_ptr<pieces::ipv6_tcp_server> server,
               std::shared_ptr<pieces::ssl> ssl) {

  for (;;) {
    auto ctx = server->get_context();

    if (fork() == 0) {
      server->stop();
      server.reset();
      return client(ssl->new_stream(ctx.fd));
    }

    ctx.free();
  }
}

int main() {
  try {

    auto server = std::make_shared<pieces::ipv6_tcp_server>(4433);

    server->sync_acceptor();

    auto ssl = std::make_shared<pieces::ssl>("/etc/ssl/localcerts/apache.pem",
                                             "/etc/ssl/localcerts/apache.key");

    websocket(std::move(server), std::move(ssl));

  } catch (std::exception &ec) {
    std::cerr << ec.what() << std::endl;
  }

  return 0;
}
