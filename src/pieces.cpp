#include <cstddef>
#include <cstdint>
#include <netinet/in.h>
#include <pieces.hpp>
#include <sys/socket.h>
#include <immintrin.h>

/* Pieces library */

/*
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

namespace pieces {
template <>
sockaddr *server<sockaddr_in6, uint16_t>::address_t::get_addr(uint16_t port) {
  addr.sin6_port = htons(port);
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_any;
  return reinterpret_cast<sockaddr *>(&addr);
};

template<>
std::size_t server<sockaddr_in6, uint16_t>::address_t::get_size(){
  return sizeof(sockaddr_in6);
}

template<>
std::tuple<int, int, int> server<sockaddr_in6, uint16_t>::address_t::get_socket_attr(){
  return {AF_INET6, SOCK_STREAM, 0};
};

}; // namespace pieces