# http-proxy-over-socks5

convert a socks5 server to http proxy server

## Environment Variables

* `PROXY_LISTEN`, address to listen, default to `:1087`
* `UPSTREAM_ADDR`, address of upstream socks5 server, default to `127.0.0.1:1080`

* `PROXY_USERNAME`, `PROXY_PASSWORD`, optional authentication for http proxy server
* `UPSTREAM_USERNAME`, `UPSTREAM_PASSWORD`, optional credentials for upstream socks5 server

* `PROXY_TLS_CRT`, `PROXY_TLS_KEY`, optional certificate files for https

## Donation

View https://guoyk.xyz/donation

## Credits

Guo Y.K., MIT License