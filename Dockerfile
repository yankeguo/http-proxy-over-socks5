FROM golang:1.20 AS builder
ENV CGO_ENABLED 0
WORKDIR /go/src/app
ADD . .
RUN go build -o /http-proxy-over-socks5

FROM alpine:3.17
RUN apk add --no-cache tini
COPY --from=builder /http-proxy-over-socks5 /http-proxy-over-socks5
ENTRYPOINT ["tini", "--"]
CMD ["/http-proxy-over-socks5"]
