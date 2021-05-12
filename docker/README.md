# Deployment using Docker

## Building a Docker image

Docker image of `encrypted-dns-server-modns` can be build as

```:bash
$ cd docker
$ docker-compose build
```

A pre-built docker image is also available at [Docker Hub](https://hub.docker.com/r/jqtype/encrypted-dns-server-modns) (`jqtype/encrypted-dns-server-modns`).

## Configuration

`.env` file must be configured as follows.

```
DOMAIN_NAME=<domain name as you like>
IPV4_ADDR=<ipv4 address exposed to the network>
PORT=50443

# if this true, you can see debug messages
#DEBUG=true

# log rotation
LOGROTATE_SIZE=10M
LOGROTATE_NUM=10
```

If you pass `DEBUG=true` in `.env` file, you can see the debug messages.

## Run

You can run `encrypted-dns-server-modns` via

```:bash
$ docker-compose up -d
```

In the default configuration, Quad9 (`9.9.9.9:53`) is used as the upstream Do53 server when `encrypted-dns-server-modns` is used as the target DNSCrypt v2 resolver. You can change it as you like by modifying `encrypted-dns.toml.in`.
