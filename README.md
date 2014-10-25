twisted-connect-proxy
=====================

Default Twisted does not ship with a CONNECT-enabled HTTP(s) proxy.  This code provides one.

This code also provides an HTTP CONNECT proxy client that implements `IReactorTCP` and `IReactorSSL`

Proxy Server
------------

To run an HTTP CONNECT proxy server on port 8080, run:

  ./server.py

That was easy.

Proxy Client
------------

The HTTP CONNECT proxy reactor can be used like this:
```python
proxy = HTTPProxyConnector(proxy_host, proxy_port)

```
