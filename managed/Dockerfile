FROM ubuntu:24.04 AS probe
RUN apt-get update && apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*
COPY probe.c /tmp/probe.c
RUN x86_64-w64-mingw32-gcc -Os -s /tmp/probe.c -o /tmp/probe.exe -lwinhttp

FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
ARG CAPE_COMMIT=3f6a2abff0eb7420f0bf78386208fe270fc16945
ARG COMMUNITY_COMMIT=8056eedab2eb05516f28d5a75c332964d0136624
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git curl python3 python3-venv python3-dev build-essential pkg-config \
    libffi-dev libssl-dev libmagic1 libfuzzy-dev libjpeg-dev zlib1g-dev \
    libmsi-dev libgcab-dev libglib2.0-dev libpcap-dev libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
RUN git init /opt/CAPEv2 && cd /opt/CAPEv2 \
    && git remote add origin https://github.com/kevoreilly/CAPEv2.git \
    && git fetch --depth 1 origin ${CAPE_COMMIT} && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$CAPE_COMMIT"
RUN python3 -m venv /opt/uv && /opt/uv/bin/pip install --no-cache-dir uv==0.9.7 \
    && cd /opt/CAPEv2 && /opt/uv/bin/uv sync --frozen --no-dev --no-install-project
RUN git init /tmp/community && cd /tmp/community \
    && git remote add origin https://github.com/CAPESandbox/community.git \
    && git fetch --depth 1 origin ${COMMUNITY_COMMIT} && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$COMMUNITY_COMMIT" \
    && cp -a analyzer/. /opt/CAPEv2/analyzer/ \
    && cp -a modules/signatures/. /opt/CAPEv2/modules/signatures/ \
    && cp -a data/. /opt/CAPEv2/data/ \
    && rm -rf /tmp/community /root/.cache /opt/CAPEv2/.git \
    && mkdir -p /opt/CAPEv2/.git/refs/heads \
    && echo 'ref: refs/heads/pinned' > /opt/CAPEv2/.git/HEAD \
    && echo "$CAPE_COMMIT" > /opt/CAPEv2/.git/refs/heads/pinned
# The pcap group only satisfies CAPE's startup check; guest traffic is captured by QEMU filter-dump.
RUN userdel ubuntu && groupadd pcap && useradd --create-home --uid 1000 --groups pcap cape \
    && mkdir -p /opt/CAPEv2/custom/conf /opt/CAPEv2/db /evidence \
    && rm -rf /opt/CAPEv2/storage /opt/CAPEv2/log \
    && chown -R cape:cape /opt/CAPEv2 /evidence
USER root
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=probe /tmp/probe.exe /opt/stealerforge-managed/probe.exe
COPY qmp.py configure.py controller.py netsim.py netsetup.sh /opt/stealerforge-managed/
COPY machinery.py /opt/CAPEv2/modules/machinery/stealerforge.py
COPY sysmon_export.py /opt/CAPEv2/analyzer/windows/modules/auxiliary/sysmon_export.py
# The Sysmon channel is exported whole by sysmon_export.py; CAPE's evtx module must not wipe it.
RUN sed -i '/"Microsoft-Windows-Sysmon\/Operational",/d' /opt/CAPEv2/analyzer/windows/modules/auxiliary/evtx.py \
    && ! grep -q 'Microsoft-Windows-Sysmon/Operational' /opt/CAPEv2/analyzer/windows/modules/auxiliary/evtx.py
ENV PATH="/opt/CAPEv2/.venv/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/CAPEv2
USER cape
ENTRYPOINT ["python", "/opt/stealerforge-managed/controller.py"]
