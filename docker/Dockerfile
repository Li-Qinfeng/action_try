# 可被 GitHub Actions 覆盖的上游参数
ARG BASE_IMAGE=vllm/vllm-openai
ARG BASE_TAG=v0.9.2
FROM ${BASE_IMAGE}:${BASE_TAG}

SHELL ["/bin/sh","-lc"]

# === 0) 目标路径：vLLM 入口脚本（按你当前版本为 3.12 路径）===
# 如上游换了 Python 次版本，可在 CI 中覆盖此变量，或在这里调整
ARG VLLM_API_SERVER=/usr/local/lib/python3.12/dist-packages/vllm/entrypoints/openai/api_server.py

# 防呆：确认上游路径存在（若不存在就 fail，并列出相近目录帮助定位）
RUN test -f "$VLLM_API_SERVER" || ( \
    echo "ERROR: Expected vLLM api_server.py at: $VLLM_API_SERVER" >&2; \
    echo "Listing nearby paths for diagnosis:" >&2; \
    ls -alh /usr/local/lib/python3.*/*-packages/vllm/entrypoints/openai/ || true; \
    exit 1 \
)

# === 1) 覆盖入口 Python 脚本 ===
COPY docker/overlay/patched/api_server.py "$VLLM_API_SERVER"

# === 2) 植入 Rust 二进制 ===
COPY docker/overlay/bin/roguard /usr/local/bin/roguard
RUN chmod +x /usr/local/bin/roguard

# === 3) 你原有的裁剪逻辑 ===

# P1：编辑/外传/调试/构建链（去掉 *编译相关* 的那些）
RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
    SUDO_FORCE_REMOVE=yes apt-get purge -y --auto-remove \
      vim vim-tiny nano less sudo \
      curl wget openssh-client rsync netcat-openbsd socat ftp telnet \
      gdb ltrace strace \
      git subversion mercurial \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# P2：补装通道（pip/venv/apt 前端）
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove \
      python3-pip python3-venv software-properties-common apt \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/bin/pip /usr/bin/pip3 /usr/local/bin/pip /usr/local/bin/pip3 || true

# 禁用 bash（保留 /bin/sh）
RUN rm -f /bin/bash || true

# 瘦身
RUN rm -rf /usr/share/man/* /usr/share/doc/* /var/cache/* /var/log/*

# 元数据（便于审计/去重）
LABEL io.vllm.upstream.ref="${BASE_IMAGE}:${BASE_TAG}"
