FROM golang:1.22-alpine AS build
RUN go install github.com/OJ/gobuster/v3@latest

FROM alpine:3.19
COPY --from=build /go/bin/gobuster /usr/local/bin/gobuster
COPY lists /lists
RUN apk add --no-cache ca-certificates
ENTRYPOINT ["gobuster"]
