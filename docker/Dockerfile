# ===== 上游镜像参数（由 Actions 传入；本地不传则用 latest）=====
ARG BASE_IMAGE=vllm/vllm-openai
ARG BASE_TAG=latest
FROM ${BASE_IMAGE}:${BASE_TAG}

SHELL ["/bin/sh","-lc"]

# 1) 植入 Rust 二进制
COPY docker/overlay/bin/roguard /usr/local/bin/roguard
RUN chmod +x /usr/local/bin/roguard

# 2) 覆盖入口 Python 脚本（动态定位 vllm 安装路径）
COPY docker/overlay/patched/api_server.py /tmp/api_server.py
RUN python3 - <<'PY'
import importlib, pathlib, shutil, sys
try:
    m = importlib.import_module("vllm")
except Exception as e:
    sys.exit(f"ERROR: cannot import vllm: {e}")
pkg_root = pathlib.Path(m.__file__).parent
dst_dir  = pkg_root / "entrypoints" / "openai"
dst      = dst_dir / "api_server.py"
print("Detected vllm package root:", pkg_root)
print("Target dir:", dst_dir)
if not dst_dir.exists():
    sys.exit(f"ERROR: target dir not found: {dst_dir}")
if dst.exists():
    shutil.copy2(dst, str(dst) + ".bak")
shutil.copy2("/tmp/api_server.py", dst)
print("Replaced:", dst)
PY

# 3) 你的裁剪逻辑（保持不变）
RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
    SUDO_FORCE_REMOVE=yes apt-get purge -y --auto-remove \
      vim vim-tiny nano less sudo \
      curl wget openssh-client rsync netcat-openbsd socat ftp telnet \
      gdb ltrace strace \
      git subversion mercurial \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove \
      python3-pip python3-venv software-properties-common apt \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/bin/pip /usr/bin/pip3 /usr/local/bin/pip /usr/local/bin/pip3 || true

RUN rm -f /bin/bash || true
RUN rm -rf /usr/share/man/* /usr/share/doc/* /var/cache/* /var/log/*

# 4) 元数据（FROM 后重新声明 ARG，避免 UndefinedVar）
ARG BASE_IMAGE
ARG BASE_TAG
LABEL io.vllm.upstream.ref="${BASE_IMAGE}:${BASE_TAG}"
