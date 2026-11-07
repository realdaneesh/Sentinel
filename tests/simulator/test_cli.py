import json
import subprocess
import sys
from pathlib import Path

import pytest

from services.simulator import generate_events
from services.simulator.__main__ import main


ROOT = Path(__file__).resolve().parents[2]
BASE_ARGS = ["--scenario", "normal_activity", "--seed", "42"]


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "services.simulator", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=15,
    )


@pytest.mark.parametrize("format_name", ["json", "jsonl"])
def test_module_cli_exports_reproducible_utf8_files(tmp_path, format_name):
    first = tmp_path / f"first.{format_name}"
    second = tmp_path / f"second.{format_name}"
    for path in (first, second):
        result = run_cli(*BASE_ARGS, "--output", str(path), "--format", format_name)
        assert result.returncode == 0, result.stderr
        assert result.stdout == ""
        assert result.stderr == ""
    assert first.read_bytes() == second.read_bytes()
    assert b"\r\n" not in first.read_bytes()
    content = first.read_text(encoding="utf-8")
    events = json.loads(content) if format_name == "json" else [json.loads(line) for line in content.splitlines()]
    assert events == generate_events("normal_activity", seed=42)


def test_cli_passes_count_and_reference_time(tmp_path):
    path = tmp_path / "burst.json"
    result = run_cli("--scenario", "failed_login_burst", "--seed", "-7", "--count", "7",
                     "--reference-time", "2025-01-01T00:00:00.123456+00:00", "--output", str(path))
    assert result.returncode == 0, result.stderr
    events = json.loads(path.read_text(encoding="utf-8"))
    assert len(events) == 7
    assert events[-1]["timestamp"] == "2025-01-01T00:00:00.123456Z"


def test_existing_file_requires_explicit_overwrite(tmp_path, capsys):
    path = tmp_path / "existing.json"
    original = b"preserve existing work\x00\xff"
    path.write_bytes(original)
    with pytest.raises(SystemExit) as error:
        main([*BASE_ARGS, "--output", str(path)])
    assert error.value.code == 2
    assert "--overwrite" in capsys.readouterr().err
    assert path.read_bytes() == original
    assert main([*BASE_ARGS, "--output", str(path), "--overwrite"]) == 0
    assert json.loads(path.read_text(encoding="utf-8")) == generate_events("normal_activity", seed=42)


def test_output_is_required_and_no_file_is_created(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as error:
        main(BASE_ARGS)
    assert error.value.code == 2
    assert "--output" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_help_does_not_require_output():
    result = run_cli("--help")
    assert result.returncode == 0
    assert "--overwrite" in result.stdout


@pytest.mark.parametrize("extra", [
    ["--scenario", "unknown"], ["--seed", "bad"], ["--count", "bad"],
    ["--count", "1"], ["--count", "10001"], ["--count", "-1"],
    ["--scenario", "failed_login_burst", "--count", "4"],
    ["--scenario", "unfamiliar_device", "--count", "3"],
    ["--scenario", "unfamiliar_ip", "--count", "3"],
    ["--format", "csv"], ["--reference-time", "2026-11-04T12:00:00"],
    ["--reference-time", "2026-11-04T12:00:00+05:30"],
    ["--reference-time", "2026-02-30T12:00:00Z"],
    ["--reference-time", "2026-11-04T12:00:00.1234567Z"],
    ["--reference-time", "0001-01-01T00:00:00Z"],
    ["--unknown-option"],
])
def test_invalid_arguments_leave_existing_output_untouched(tmp_path, extra, capsys):
    path = tmp_path / "preserved.json"
    path.write_text("existing", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        main([*BASE_ARGS, "--output", str(path), "--overwrite", *extra])
    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == "existing"


@pytest.mark.parametrize("output", ["https://example.invalid/events", "//server/share/events", "\\\\server\\share\\events", " "])
def test_remote_and_empty_output_paths_are_rejected(output, capsys):
    with pytest.raises(SystemExit) as error:
        main([*BASE_ARGS, "--output", output])
    assert error.value.code == 2
    assert "local file path" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["missing_parent", "directory"])
def test_filesystem_errors_are_reported_without_tracebacks(tmp_path, kind, capsys):
    output = tmp_path / "missing" / "events.json" if kind == "missing_parent" else tmp_path
    with pytest.raises(SystemExit) as error:
        main([*BASE_ARGS, "--output", str(output), "--overwrite"])
    assert error.value.code == 2
    stderr = capsys.readouterr().err
    assert "error:" in stderr
    assert "Traceback" not in stderr


@pytest.mark.parametrize("args", [[], ["--scenario", "normal_activity"], ["--seed", "1"]])
def test_required_arguments(tmp_path, args, capsys):
    output = tmp_path / "events.json"
    with pytest.raises(SystemExit) as error:
        main([*args, "--output", str(output)])
    assert error.value.code == 2
    assert "required" in capsys.readouterr().err
    assert not output.exists()
