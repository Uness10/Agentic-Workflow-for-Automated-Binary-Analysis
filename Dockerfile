FROM python:3.12-slim-bookworm

# ---------- system deps ----------
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    git \
    build-essential \
    file \
    binutils \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# ---------- upx ----------
# Debian bookworm repositories may not provide an `upx` package, so install
# a pinned upstream release binary.
ARG UPX_VERSION=4.2.4
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) upx_arch="amd64" ;; \
      arm64) upx_arch="arm64" ;; \
      *) echo "Unsupported architecture for UPX: $arch"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/upx.tar.xz "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-${upx_arch}_linux.tar.xz"; \
    tar -xJf /tmp/upx.tar.xz -C /tmp; \
    install -m 0755 "/tmp/upx-${UPX_VERSION}-${upx_arch}_linux/upx" /usr/local/bin/upx; \
    rm -rf /tmp/upx.tar.xz "/tmp/upx-${UPX_VERSION}-${upx_arch}_linux"


# ---------- app ----------
WORKDIR /app
COPY . /app
RUN chmod +x /app/start.sh

# ---------- python deps ----------
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[dev]"

# ---------- compile test samples ----------
RUN if [ -f /app/samples/fake_malware.c ]; then \
        gcc -o /app/samples/fake_malware /app/samples/fake_malware.c -no-pie; \
    fi
RUN if [ -f /app/samples/test.c ]; then \
        gcc -o /app/samples/test /app/samples/test.c -no-pie; \
    fi
RUN if [ -f /app/samples/mock.c ]; then \
        gcc -o /app/samples/mock /app/samples/mock.c -no-pie; \
    fi

# ---------- non-root ----------
RUN useradd -m analyst && \
    chown -R analyst:analyst /app
USER analyst

# ---------- health ----------
HEALTHCHECK CMD python -c "import lief, pefile" || exit 1

CMD ["/bin/bash", "./start.sh"]