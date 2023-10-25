# pieces - websocket
My websocket implementation

This is a non-compliant C++ websocket server implementation using OpenSSL.

**You could find a usage example in src/main.cpp.** 

For now, it only read frames, respond pings, and close connection. The 
example is not complete, and the final version will use fork() to separate users.

Separate users by process with fork() is a secure feature for not to share the 
same memory between peers.

This server has an experimental feature that allows it to jump the http/1.1 handshake 
using *ALPN (Application-Layer Protocol Negotiation)* with the IANA name "wss". 
This name is not available yet.

It supposed to be POSIX complaint with the minimum dependencies using C++ 23 or
newer standards and OpenSSL.