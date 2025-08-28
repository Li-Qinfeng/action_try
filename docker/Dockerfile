# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=vllm/vllm-openai
ARG BASE_TAG=latest

# 源码目录（相对仓库根 = build context 根）
ARG ROGUARD_SRC=docker/overlay/roguard-src

# ---- [Stage 1] Rust 构建阶段 ----
FROM rust:1-bullseye AS roguard-builder
ARG ROGUARD_SRC
WORKDIR /src/roguard

# 先拷清单（利于缓存）
COPY ${ROGUARD_SRC}/Cargo.toml ./
RUN test -f Cargo.toml || (echo "ERROR: ${ROGUARD_SRC}/Cargo.toml not found" && false)

# 再拷源码
COPY ${ROGUARD_SRC}/src ./src
RUN test -f src/main.rs || (echo "ERROR: ${ROGUARD_SRC}/src/main.rs not found" && false)

# BuildKit 缓存加速
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/roguard/target \
    cargo build --release

# 瘦身（无 strip 也不报错）
RUN strip target/release/roguard || true

# ---- [Stage 2] 最终运行镜像 ----
FROM ${BASE_IMAGE}:${BASE_TAG}
SHELL ["/bin/sh","-lc"]

# 1) 植入 Rust 二进制
COPY --from=roguard-builder /src/roguard/target/release/roguard /usr/local/bin/roguard
RUN chmod +x /usr/local/bin/roguard

# 2) 插入 api_server 补丁（保持你的逻辑）
COPY docker/overlay/patched/api_server_patch.py /tmp/api_server_patch.py
RUN python3 - <<'PY'
import importlib, pathlib, sys
def die(msg,code=1): print(msg,file=sys.stderr); sys.exit(code)
try: m=importlib.import_module("vllm")
except Exception as e: die(f"ERROR: cannot import vllm: {e}")
pkg_root=pathlib.Path(m.__file__).parent
dst_dir=pkg_root/"entrypoints"/"openai"; dst=dst_dir/"api_server.py"
patch=pathlib.Path("/tmp/api_server_patch.py")
if not dst_dir.exists(): die(f"ERROR: target dir not found: {dst_dir}")
if not dst.exists(): die(f"ERROR: target file not found: {dst}")
patch_text=patch.read_text(encoding="utf-8"); orig_text=dst.read_text(encoding="utf-8")
if patch_text.strip() in orig_text: print("Patch already present. Skip",dst); sys.exit(0)
lines=orig_text.splitlines(keepends=True); i=0
while i<len(lines) and lines[i].lstrip().startswith("# SPDX-"): i+=1
new="".join(lines[:i])+patch_text+("\n" if not patch_text.endswith("\n") else "")+"".join(lines[i:])
dst.with_suffix(".py.bak").write_text(orig_text,encoding="utf-8")
dst.write_text(new,encoding="utf-8")
print("Patched (prepended):", dst)
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

ARG BASE_IMAGE
ARG BASE_TAG
LABEL io.vllm.upstream.ref="${BASE_IMAGE}:${BASE_TAG}"
