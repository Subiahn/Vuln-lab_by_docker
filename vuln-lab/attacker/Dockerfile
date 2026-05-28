FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    sqlmap \
    netcat-traditional \
    python3 \
    python3-pip \
    git \
    vim \
    jq \
    iputils-ping \
    dnsutils \
    perl \
    libnet-ssleay-perl \
    libwww-perl \
    hashcat \
    john \
    && rm -rf /var/lib/apt/lists/*

# nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# gobuster
RUN wget -q "https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz" \
    -O /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm /tmp/gobuster.tar.gz

# wordlist
RUN mkdir -p /usr/share/wordlists \
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    -O /usr/share/wordlists/common.txt || true \
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt" \
    -O /usr/share/wordlists/rockyou-75.txt || true

# Python 도구
RUN pip3 install --break-system-packages \
    pwntools \
    requests \
    beautifulsoup4 \
    PyJWT \
    flask

# JWT 테스트 스크립트
RUN mkdir -p /workspace/scripts
COPY scripts/ /workspace/scripts/

RUN mkdir -p /workspace/exploits /workspace/reports /workspace/loot

COPY motd.sh /etc/profile.d/motd.sh
RUN chmod +x /etc/profile.d/motd.sh

WORKDIR /workspace
CMD ["/bin/bash"]
