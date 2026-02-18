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

# ---------- radare2 (avoid snapd in containers) ----------
# Install radare2 from the distro package instead of using snapd,
# because snapd requires systemd/socket activation not available in containers.


# ---------- python deps ----------
WORKDIR /app
COPY pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[dev]"

# ---------- app ----------
COPY . /app



# ---------- non-root ----------
RUN useradd -m analyst && \
    chown -R analyst:analyst /app
USER analyst

# ---------- health ----------
HEALTHCHECK CMD python -c "import lief, pefile, r2pipe" || exit 1

CMD ["bash"]