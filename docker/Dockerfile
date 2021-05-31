FROM ubuntu:20.04
LABEL maintainer="Jun Kurihara"

SHELL ["/bin/sh", "-x", "-c"]
ENV SERIAL 2

ENV CFLAGS=-Ofast
ENV BUILD_DEPS   curl make build-essential git libevent-dev libexpat1-dev autoconf file libssl-dev byacc
ENV RUNTIME_DEPS bash util-linux coreutils findutils grep libssl1.1 ldnsutils libevent-2.1-7 expat ca-certificates runit runit-helper jed logrotate

ENV MODNS_GIT_URL https://github.com/junkurihara/encrypted-dns-server-modns
ENV MODNS_GIT_BRANCH peeling_header

RUN apt update && apt -qy dist-upgrade && apt -qy clean && \
    apt install -qy --no-install-recommends $RUNTIME_DEPS && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log

RUN update-ca-certificates 2> /dev/null || true

WORKDIR /tmp

ENV RUSTFLAGS "-C link-arg=-s"

RUN apt update && apt install -qy --no-install-recommends $BUILD_DEPS && \
    curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain stable && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    echo "Building encrypted-dns-modns from source" && \
    git clone $MODNS_GIT_URL encrypted-dns-server && \
    cd encrypted-dns-server && \
    git checkout $MODNS_GIT_BRANCH && \
    cargo build --release && \
    mkdir -p /opt/encrypted-dns/sbin && \
    mv /tmp/encrypted-dns-server/target/release/encrypted-dns-modns ~/.cargo/bin/encrypted-dns && \
    mv ~/.cargo/bin/encrypted-dns /opt/encrypted-dns/sbin/ && \
    strip --strip-all /opt/encrypted-dns/sbin/encrypted-dns && \
    mkdir -p /opt/encrypted-dns/etc && \
    mv /tmp/encrypted-dns-server/undelegated.txt /opt/encrypted-dns/etc/ && \
    apt -qy purge $BUILD_DEPS && apt -qy autoremove && \
    rm -fr ~/.cargo ~/.rustup && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log

RUN groupadd _encrypted-dns && \
    mkdir -p /opt/encrypted-dns/empty && \
    useradd -g _encrypted-dns -s /etc -d /opt/encrypted-dns/empty _encrypted-dns && \
    mkdir -m 700 -p /opt/encrypted-dns/etc/keys && \
    mkdir -m 700 -p /opt/encrypted-dns/etc/lists && \
    chown _encrypted-dns:_encrypted-dns /opt/encrypted-dns/etc/keys && \
    mkdir -m 700 -p /opt/dnscrypt-wrapper/etc/keys && \
    mkdir -m 700 -p /opt/dnscrypt-wrapper/etc/lists && \
    chown _encrypted-dns:_encrypted-dns /opt/dnscrypt-wrapper/etc/keys

RUN mkdir -p \
    /etc/service/watchdog

COPY docker/encrypted-dns.toml.in /opt/encrypted-dns/etc/

COPY docker/entrypoint.sh /

COPY docker/encrypted-dns.sh /etc/service/encrypted-dns/run

COPY docker/watchdog.sh /etc/service/watchdog/run

VOLUME ["/opt/encrypted-dns/etc/keys"]

EXPOSE 443/udp 443/tcp 9100/tcp

CMD ["/entrypoint.sh", "start"]

ENTRYPOINT ["/entrypoint.sh"]
