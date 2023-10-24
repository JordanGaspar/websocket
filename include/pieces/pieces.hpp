#ifndef PIECES_HPP_
#define PIECES_HPP_
#include <cstdlib>
#include <iostream>
#include <sstream>
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

#include <bits/types/FILE.h>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <list>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>
#include <queue>
#include <ranges>
#include <shared_mutex>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <tuple>
#include <csignal>
#include <memory>
#include <algorithm>
#include <cstring>
#include <span>
#include <unistd.h>

namespace pieces {

/*! A thread safe queue

Usage:

  - In the producer thread, lock the queue with safe_queue::safe_lock, storing
the return value;
  - Do your job normally with the producer thread, with safe_lock it's thread
safe now;
  - On the end, make use safe_queue::safe_notify to tell the consumers threads
that job was done;
  - On consumer thread, lock the queue with safe_queue::safe_lock and do your
job. If no more jobs,
  - you could wait for more work using safe_queue::safe_wait.

  Example:

      #include <iostream>
      #include <pieces.hpp>
      #include <thread>

      int main() {

        pieces::safe_queue<int> q;

        std::thread t1{([&]() {
          auto lock = q.safe_lock();
          q.safe_wait(lock);
          q.push(6);
        })};

        std::thread t2{[&]() {
          auto lock = q.safe_lock();
          q.push(7);
          q.safe_notify();
        }};

        t1.join();
        t2.join();

        while (!q.empty()) {
          std::cout << q.front() << std::endl;
          q.pop();
        }

        return 0;
      }
*/
template <typename Tp>
class safe_queue : public std::queue<Tp>,
                   private std::shared_mutex,
                   private std::condition_variable_any {
public:
  //! The safe_lock_t type returned by safe_queue::safe_lock method.
  typedef std::unique_lock<std::shared_mutex> safe_lock_t;

  //! A normal constructor only to initialize the iherited classes.
  safe_queue()
      : std::queue<Tp>{}, std::shared_mutex{}, std::condition_variable_any{},
        cv_wait{false} {}

  //! Lock the safe_queue object and return a unique lock.
  //! At the end of the scope, it's unlocked automatically.
  safe_lock_t safe_lock() { return safe_lock_t(*this); }

  //! Block to wait a notification from producer thread.
  //! It needs an object returned by safe_lock as argument.
  //! When blocked, the lock is unlocked and this function blocks
  //! waiting the new notification called by safe_notify().
  void safe_wait(std::unique_lock<std::shared_mutex> &lock) {
    set_wait();

    while (get_wait()) {
      wait(lock);
    }
  }

  //! This function unblock safe_wait on consumer threads.
  //! You need to use it in the producer thread to notify
  //! the consumers that are more work to be done.
  void safe_notify() {
    if (get_wait()) {
      unset_wait();
      notify_all();
    }
  }

private:
  //! Private method to set this object in waiting state.
  void set_wait() { cv_wait = true; };
  //! Private method to get waiting state.
  bool get_wait() { return cv_wait; };
  //! Private method to release waiting state.
  void unset_wait() { cv_wait = false; };
  //! Private variable that keep the wait state.
  bool cv_wait;
};

/*! Generic template class to configure servers.

Usage:

  int main(){
    pieces::ipv6_tcp_server server(8080);
    int fd = server.get_fd();
  }

*/
template <typename Tp = sockaddr_in6, typename Pp = uint16_t> class server {
public:
  //! Public type context_t with three fields:
  //! fd for file descriptor, addr to the address
  //! structure and len to the addr size.
  struct context_t {
    int fd;
    Tp addr;
    socklen_t len;
  };

  //! Sigint handler to close the main file descriptor.
  static void sigint_handler(int sig){
    if (sig == SIGINT){
      close(fd);
      exit(EXIT_SUCCESS);
    }
  }

  //! Generic constructor to create an file descriptor that can be
  //! obteined with server::get_fid() method after the construction.
  //! It receives port or path as argument. The default configuration
  //! is to run an ipv6 tcp file descriptor.
  server(Pp port_path) {
    int ec = 0;
 
    address_t addr;

    auto [domain, type, protocol] = addr.get_socket_attr();

    fd = socket(domain, type, protocol);
    error(fd, "socket error");

    ec = bind(fd, addr.get_addr(port_path), addr.get_size());
    error(ec, "bind error");

    ec = listen(fd, SOMAXCONN);
    error(ec, "listen error");

    //! Ignore SIGPIPE of write
    std::signal(SIGPIPE, SIG_IGN);

    //! Catch the sigint interruption to close the server 
    //! smoothly.
    std::signal(SIGINT, sigint_handler);
  };

  ~server(){
    close(get_fd());
  }

  //! Function that accepts new connections in async mode.
  //! It put the accepted socket into the safe queue to be
  //! consumed by the consumer thread.
  void sync_acceptor() {

    std::thread thrd([&]() {
      for (;;) {
        context_t ctx;

        ctx.fd =
            accept(get_fd(), reinterpret_cast<sockaddr *>(&ctx.addr), &ctx.len);

        if (ctx.fd != -1) {
          auto lock = queue.safe_lock();
          queue.push(std::move(ctx));
          queue.safe_notify();
        }
      }
    });

    thrd.detach();
  }

  //! Function to get context_t from queue. If queue is empty this function
  //! blocks to wait for more content.
  context_t get_context() {

    context_t context;

    {
      auto lock = queue.safe_lock();
      while (queue.empty()) {
        queue.safe_wait(lock);
      }

      context.fd = queue.front().fd;
      context.addr = queue.front().addr;
      context.len = queue.front().len;
      queue.pop();
    }

    return context;
  }

  //! It does the same that get_context but without
  //! blocking. In case of a empty queue, it returns 
  //! an std::nullopt indicating a empty queue.
  std::optional<context_t> nonblock_get_context(){
    context_t context;
    {
      auto lock = queue.safe_lock();

      if (queue.empty()){
        return std::nullopt;
      }

      context.fd = queue.front().fd;
      context.addr = queue.front().addr;
      context.len = queue.front().len;
      queue.pop();
    }
    return context;
  }

private:
  //! Function to get the prepared file descriptor.
  int get_fd() { return fd; }

  //! Private context_t queue.
  safe_queue<context_t> queue;

  //! Private member to check for errors in constructor.
  void error(int ec, const char *msg) {
    if (ec == -1) {
      throw std::runtime_error(msg);
    }
  }

  //! An inner class to obtain the necessary sockaddr object to
  //! feed constructor methods.
  class address_t {
  public:
    //! The address_t constructor that zeros the addr object.
    address_t() : addr{0} {};

    //! This method receive the ip or the path and construct the
    //! sockaddr object to be used in constructor. It's virtual so
    //! it can be used to get another types of server like unix
    //! stream sockets.
    virtual sockaddr *get_addr(Pp port_path);

    //! Function to get addr object size to be used address_t in constructor.
    virtual std::size_t get_size();

    //! Get attributes to be used in bind method on the address_t constructor.
    virtual std::tuple<int, int, int> get_socket_attr();

  private:
    //! The private address object.
    Tp addr;
  };

  //! The file descriptor to be stored by the server class.
  static int fd;
};

//! The file descriptor need to be in global scope to be closed 
//! by sigint handler.
template<typename Tp, typename Pp>
int server<Tp, Pp>::fd = 0;

//! The typename to represent ipv6 tcp server.
typedef server<> ipv6_tcp_server;

/* Class that create an SSL context for the creation of 
specific client ssl stream.
*/
class ssl {

private:
  //! callback to select the ALPN (Application Layer Protocol Negotiation).
  static int alpn_select_callback(SSL *ssl, const unsigned char **out,
                                  unsigned char *outlen,
                                  const unsigned char *in, unsigned int inlen,
                                  void *arg) {

    //! Here, we have the supported protocol list. This list
    //! already has the wss alpn protocol support.
    //! Supported protocols are http/1.1 and wss.
    static unsigned char protocol[] = {3,   'w', 's', 's', 8,   'h', 't',
                                       't', 'p', '/', '1', '.', '1'};

    unsigned char *output;
    unsigned char len;

    if (SSL_select_next_proto(&output, &len, protocol, sizeof(protocol), in,
                              inlen) == OPENSSL_NPN_NO_OVERLAP) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (std::strncmp(reinterpret_cast<const char *>(output), "wss", len) == 0) {
      bool *WSS_ALPN = (bool *)arg;
      *WSS_ALPN = true;
    }

    *out = output;
    *outlen = len;

    return SSL_TLSEXT_ERR_OK;
  }

public:
  //! ssl class constructor that receives two arguments
  //! with certificate file and private key file, both in
  //! pem file format.
  ssl(const char *cert_file, const char *privkey_file) {
    ssl_ctx = SSL_CTX_new(TLS_method());

    if (ssl_ctx == NULL) {
      throw std::runtime_error("ssl context creation error");
    }

    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION) != 1) {
      throw std::runtime_error("minimum protocol version error");
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) !=
        1) {
      throw std::runtime_error("certificate file error");
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, privkey_file, SSL_FILETYPE_PEM) !=
        1) {
      throw std::runtime_error("private key error");
    }

    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_callback, &WSS_ALPN);
  }

  //! stream object with private constructor to be used by ssl stream
  //! creation method.
  class stream {
  private:
    SSL *s;
    int fd_;
    bool graceful;

  public:
    //! ssl is a friend class of stream because only ssl can create streams.
    friend class ssl;

  protected:
    //! streams are only created by ssl object, so protected member.
    stream(SSL_CTX *ssl_ctx, int fd) : fd_{fd}, graceful(false) {
      s = SSL_new(ssl_ctx);

      if (s == NULL) {
        throw std::runtime_error("ssl stream creation error");
      }

      if (SSL_set_fd(s, fd_) == 0) {
        throw std::runtime_error("ssl set file descriptor error");
      }

      if (SSL_accept(s) < 1) {
        throw std::runtime_error("stream accept error");
      }
    }

  public:
    //! write function of stream object with string argument.
    int write(const std::string &buffer) {
      return SSL_write(s, buffer.data(), buffer.size());
    }

    //! write function of stream object with vector argument.
    int write(const std::vector<char> &buffer) {
      return SSL_write(s, buffer.data(), buffer.size());
    }

    //! read function of stream object with string argument.
    int read(std::string *buffer) {
      return SSL_read(s, buffer->data(), buffer->size());
    }

    //! read function of stream object with vector argument.
    int read(std::vector<char> *buffer) {
      return SSL_read(s, buffer->data(), buffer->size());
    }

    //! The stream destructor that destroys the client connection and
    //! closes the socket.
    ~stream() {
      int ec = 0;

      if (graceful) {
        ec = SSL_shutdown(s);

        if (ec == 0) {
          std::vector<char> buff(100);
          SSL_read(s, buff.data(), 100);
          SSL_shutdown(s);
        }
      }

      SSL_free(s);
      close(fd_);
    }

    //! Copy constructor that duplicate ssl s object.
    stream(const stream &strm)
        : s{SSL_dup(strm.s)}, fd_{strm.fd_}, graceful{strm.graceful} {
      if (s == NULL) {
        throw std::runtime_error("ssl duplication error");
      }
    }

    //! Copy assignment that duplicate ssl s object.
    stream &operator=(const stream &strm) {
      if (this == &strm) {
        return *this;
      }

      s = SSL_dup(strm.s);
      fd_ = strm.fd_;
      graceful = strm.graceful;

      if (s == NULL) {
        throw std::runtime_error("ssl assignment error");
      }

      return *this;
    }
  };

  //! A normal destructor that calls free function.
  ~ssl() { SSL_CTX_free(ssl_ctx); }

  //! This is the stream factory function. Only ssl has 
  //! The ability to call stream constructor because it's 
  //! Protected. So we need this method for the criation.
  stream new_stream(int fd) { return stream(ssl_ctx, fd); }

  //! This function returns if this ssl connection has wss alpn 
  //! support.
  bool get_wss_alpn(){
    return WSS_ALPN;
  }

private:
  SSL_CTX *ssl_ctx;
  bool WSS_ALPN;
};


//! Concept of a object that has 'int read(std::string*)' 
//! function and 'int write(const std::string&)' function.
template <typename Tp>
concept HasReadAndWrite = requires(Tp t, std::string *i) {
  { t.read(i) } -> std::same_as<int>;
} && requires(Tp t, const std::string &j) {
  { t.write(j) } -> std::same_as<int>;
};

//! Concept to verify if it's a function with SSL properties.
template<typename Tp>
concept HasALPN = requires(Tp t) {
  {t.get_wss_alpn()} -> std::same_as<bool>; 
};

//! Template class websocket with HasReadAndWrite constraint.
template <HasReadAndWrite Tp = ipv6_tcp_server> class websocket {
public:
  //! This constructor makes a non-complient handshake.
  //! It only checks for the Sec-WebSocket-Key and returns
  //! the Sec-WebSocket-Accept. This server is thinked to
  //! use alpn in the future.
  websocket(Tp &stream) : stream_{stream} {
    if constexpr (HasALPN<Tp>) {
      if (!stream_.get_wss_alpn()) {
        http_handshake();
      }
    } else {
      http_handshake();
    }
  }

private:
  enum control_t { read, close, done };

  control_t unpack() {

    enum opcode_t {
      continuation = 0x0,
      text = 0x1,
      binary = 0x2,
      close = 0x8,
      ping = 0x9,
      pong = 0x10
    };

    bool fin = read_buffer[0] & 0b10000000;
    opcode_t opcode = read_buffer[0] & 0b00001111;
    bool mask = read_buffer[1] & 0b10000000;
    std::size_t len = read_buffer[1] & 0b01111111;
    std::size_t last_byte = 2;

    if (len == 126) {
      len = *reinterpret_cast<uint16_t *>(read_buffer[2]);

      last_byte = 4;
    }

    if (len == 127) {
      uint64_t tmp = *reinterpret_cast<uint64_t *>(read_buffer[2]);

      if (tmp & 0x8000000000000000) {
        return false;
      }

      last_byte = 10;

      len = tmp;
    }

    char *payload = &read_buffer[last_byte + 4];

    if (mask) {
      char *mask_key = &read_buffer[last_byte];

      for (int i = 0; i < len; i++) {
        payload[i] ^= mask_key[i % 4];
      }
    }

    return true;
  }

  void pack();

  //! The non-complient handshake procedure. This private
  //! method only reads the Sec-WebSocket-Key propertie and
  //! Return the Sec-WebSocket-Accept with the right values.
  void http_handshake() {
    std::string buffer(1024, 0);
    std::string base64(28, 0);
    std::string md(20, 0);
    std::string pattern("Sec-WebSocket-Key: ");
    std::string magic("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "
        "websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
    std::string end("\r\n\r\n");
    std::string error("websocket error");
    std::string error_response("HTTP/1.1 400 Bad Request\r\n\r\n");

    stream_.read(&buffer);

    auto start = buffer.find(pattern);

    if (start == std::string::npos) {
      stream_.write(error_response);
      throw std::runtime_error(error);
    }

    start += pattern.size();
    auto str = buffer.substr(start, buffer.find("\r\n", start) - start);
    str += magic;

    SHA1(reinterpret_cast<const unsigned char *>(str.data()), str.size(),
         reinterpret_cast<unsigned char *>(md.data()));

    EVP_EncodeBlock(reinterpret_cast<unsigned char *>(base64.data()),
                    reinterpret_cast<const unsigned char *>(md.data()),
                    md.size());

    response += base64 + end;

    stream_.write(response);
  }

  std::string read_buffer;
  std::string write_buffer;

  Tp &stream_;
};

}; // namespace pieces

#endif