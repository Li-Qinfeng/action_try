# syntax=docker/dockerfile:1.7

# ===== 上游镜像参数（由 Actions 传入；本地不传则用 latest）=====
ARG BASE_IMAGE=vllm/vllm-openai
ARG BASE_TAG=latest

# ---- [Stage 1] Rust 构建阶段：在独立环境里编译 roguard ----
FROM rust:1-bullseye AS roguard-builder
WORKDIR /src/roguard

# 把 Rust 源码复制进来（你已经把源码放在 action_try/docker/overlay/roguard-src/）
COPY action_try/docker/overlay/roguard-src/ ./

# 使用 BuildKit 的缓存加速（可选）
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/roguard/target \
    cargo build --release

# 尽量瘦身（不存在 strip 也不会失败）
RUN strip target/release/roguard || true

# ---- [Stage 2] 最终运行镜像：来自上游 vLLM ----
FROM ${BASE_IMAGE}:${BASE_TAG}
SHELL ["/bin/sh","-lc"]

# 1) 植入 Rust 二进制（来自上面的构建阶段）
COPY --from=roguard-builder /src/roguard/target/release/roguard /usr/local/bin/roguard
RUN chmod +x /usr/local/bin/roguard

# 2) 覆盖入口 Python 脚本（动态定位 vllm 安装路径）
#    现在改为：将 api_server_patch.py 的内容插入到 api_server.py 最前面（若存在 SPDX 头，则插在 SPDX 头之后）
COPY docker/overlay/patched/api_server_patch.py /tmp/api_server_patch.py
RUN python3 - <<'PY'
import importlib, pathlib, sys

def die(msg: str, code: int = 1):
    print(msg, file=sys.stderr)
    sys.exit(code)

try:
    m = importlib.import_module("vllm")
except Exception as e:
    die(f"ERROR: cannot import vllm: {e}")
pkg_root = pathlib.Path(m.__file__).parent
dst_dir  = pkg_root / "entrypoints" / "openai"
dst      = dst_dir / "api_server.py"
patch    = pathlib.Path("/tmp/api_server_patch.py")

print("Detected vllm package root:", pkg_root)
print("Target dir:", dst_dir)
if not dst_dir.exists():
    die(f"ERROR: target dir not found: {dst_dir}")
if not dst.exists():
    die(f"ERROR: target file not found: {dst}")

patch_text = patch.read_text(encoding="utf-8")
orig_text  = dst.read_text(encoding="utf-8")

# 幂等：已经插入过就跳过
if patch_text.strip() in orig_text:
    print("Patch already present. Skip modifying", dst)
    sys.exit(0)

# 如果文件顶部有连续的 SPDX 头，则把补丁插在 SPDX 头之后；否则直接插到文件最前面
lines = orig_text.splitlines(keepends=True)
insert_idx = 0
while insert_idx < len(lines):
    s = lines[insert_idx].lstrip()
    if s.startswith("# SPDX-"):
        insert_idx += 1
        continue
    break

new_text = "".join(lines[:insert_idx]) + patch_text + ("\n" if not patch_text.endswith("\n") else "") + "".join(lines[insert_idx:])

# 备份一次
bak = dst.with_suffix(".py.bak")
dst.write_text(new_text, encoding="utf-8")
bak.write_text(orig_text, encoding="utf-8")

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

# 4) 元数据（FROM 后重新声明 ARG，避免 UndefinedVar）
ARG BASE_IMAGE
ARG BASE_TAG
LABEL io.vllm.upstream.ref="${BASE_IMAGE}:${BASE_TAG}"
