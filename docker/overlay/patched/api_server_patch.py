if __name__ == "__main__":
    import os, sys, subprocess

    ROGUARD_BIN = os.environ.get("ROGUARD_BIN", "/usr/local/bin/roguard")

    try:
        subprocess.run([ROGUARD_BIN], check=True)
    except FileNotFoundError:
        print(f"[RO-GUARD] binary not found: {ROGUARD_BIN}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[RO-GUARD] failed with rc={e.returncode}", file=sys.stderr)
        sys.exit(e.returncode)
