FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY ipecho/server/main.go .
RUN go build -ldflags="-s -w" -o ipecho-server main.go

FROM alpine:3.19
COPY --from=builder /build/ipecho-server /usr/local/bin/
EXPOSE 9999
ENTRYPOINT ["ipecho-server"]
CMD ["9999"]
