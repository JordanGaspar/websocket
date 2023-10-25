# pieces - websocket
My websocket implementation

This is a non-compliant C++ websocket server implementation using OpenSSL.

You could find a usage example in src/main.cpp. For now, it only read 
frames, respond pings, and close connection. The example is not complete, and 
the final version will use fork() to separate users.

It supposed to be POSIX complaint with the minimum dependencies using C++ 23 or
newer standard and OpenSSL.