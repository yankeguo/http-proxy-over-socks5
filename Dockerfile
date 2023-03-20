FROM golang:1.20 AS builder
ENV CGO_ENABLED 0
WORKDIR /go/src/app
ADD . .
RUN go build -o /http-over-socks

FROM alpine:3.17
RUN apk --no-cache add tini
COPY --from=builder /http-over-socks /http-over-socks
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/http-over-socks"]
