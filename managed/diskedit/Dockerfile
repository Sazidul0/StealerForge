FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends libguestfs-tools linux-image-generic qemu-utils \
    libhivex-bin libwin-hivex-perl && rm -rf /var/lib/apt/lists/*
COPY disable-defender.sh defender.reg /opt/diskedit/
ENTRYPOINT ["sh", "/opt/diskedit/disable-defender.sh"]
