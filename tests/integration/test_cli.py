from pathlib import Path
import subprocess

fixture = Path("tests/fixtures/wx_load.elf")

result = subprocess.run(
    ["./elfguard", str(fixture)],
    capture_output=True,
    text=True,
    check=False,
)

expected_stdout = (
    f"{fixture}: valid supported ELF64 file\n"
)

expected_stderr = (
    f"{fixture}: warning: program header 0 has "
    "writable and executable permissions\n"
)

if result.returncode != 0:
    raise SystemExit(
        f"expected exit status 0, got {result.returncode}"
    )

if result.stdout != expected_stdout:
    raise SystemExit(
        "unexpected stdout:\n"
        f"expected: {expected_stdout!r}\n"
        f"actual:   {result.stdout!r}"
    )

if result.stderr != expected_stderr:
    raise SystemExit(
        "unexpected stderr:\n"
        f"expected: {expected_stderr!r}\n"
        f"actual:   {result.stderr!r}"
    )

print("All CLI integration tests passed.")