FROM python:3.11-slim

# ---------- system deps ----------
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    git \
    build-essential \
    file \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# ---------- radare2 ----------
RUN git clone --depth 1 https://github.com/radareorg/radare2.git /opt/radare2 && \
    /opt/radare2/sys/install.sh && \
    rm -rf /opt/radare2

# ---------- python deps ----------
WORKDIR /app
COPY pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[dev]"

# ---------- app ----------
COPY . /app

# ---------- permissions ----------
RUN chmod +x /app/start.sh

# ---------- non-root ----------
RUN useradd -m analyst && \
    chown -R analyst:analyst /app
USER analyst

# ---------- health ----------
HEALTHCHECK CMD python -c "import lief, pefile, r2pipe" || exit 1

CMD ["bash"]