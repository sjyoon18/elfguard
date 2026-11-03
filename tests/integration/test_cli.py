from pathlib import Path
import subprocess


def run_case(
    fixture,
    expected_returncode,
    expected_stdout,
    expected_stderr,
):
    result = subprocess.run(
        ["./elfguard", str(fixture)],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != expected_returncode:
        raise SystemExit(
            f"{fixture}: expected exit status "
            f"{expected_returncode}, got {result.returncode}"
        )

    if result.stdout != expected_stdout:
        raise SystemExit(
            f"{fixture}: unexpected stdout:\n"
            f"expected: {expected_stdout!r}\n"
            f"actual:   {result.stdout!r}"
        )

    if result.stderr != expected_stderr:
        raise SystemExit(
            f"{fixture}: unexpected stderr:\n"
            f"expected: {expected_stderr!r}\n"
            f"actual:   {result.stderr!r}"
        )


wx_fixture = Path("tests/fixtures/wx_load.elf")

run_case(
    fixture=wx_fixture,
    expected_returncode=0,
    expected_stdout=(
        f"{wx_fixture}: valid supported ELF64 file\n"
    ),
    expected_stderr=(
        f"{wx_fixture}: warning: program header 0 has "
        "writable and executable permissions\n"
    ),
)

unterminated_name_fixture = Path(
    "tests/fixtures/unterminated_section_name.elf"
)

run_case(
    fixture=unterminated_name_fixture,
    expected_returncode=1,
    expected_stdout="",
    expected_stderr=(
        f"{unterminated_name_fixture}: section header 1: "
        "section name is not null-terminated\n"
    ),
)

print("All CLI integration tests passed.")