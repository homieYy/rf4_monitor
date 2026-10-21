from types import SimpleNamespace

import pytest
import bootstrap


def test_prepare_installs_only_once_and_after_requirements_change(tmp_path, monkeypatch):
    python = tmp_path / ".venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.touch()
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("scapy\npsutil\n")
    calls = []
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0))
    assert bootstrap.prepare(tmp_path) == python
    bootstrap.prepare(tmp_path)
    assert sum("pip" in args for args in calls) == 1
    requirements.write_text("scapy\npsutil>=6\n")
    bootstrap.prepare(tmp_path)
    assert sum("pip" in args for args in calls) == 2


def test_failed_install_not_marked_complete(tmp_path, monkeypatch):
    python = tmp_path / ".venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.touch()
    (tmp_path / "requirements.txt").write_text("scapy\n")
    def invoke(argv, **kwargs):
        if "pip" in argv:
            raise bootstrap.subprocess.CalledProcessError(1, argv)
        return SimpleNamespace(returncode=1)
    monkeypatch.setattr(bootstrap.subprocess, "run", invoke)
    with pytest.raises(bootstrap.subprocess.CalledProcessError):
        bootstrap.prepare(tmp_path)
    assert not (tmp_path / ".venv" / "rf4-requirements.sha256").exists()


def test_offline_launch_preserves_space_paths_without_driver(monkeypatch):
    calls, pages = [], []
    monkeypatch.setattr(bootstrap, "prepare", lambda: "C:/a b/python.exe")
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0))
    monkeypatch.setattr(bootstrap.webbrowser, "open", pages.append)
    assert bootstrap.main(["--read", "a b.pcapng"]) == 0
    assert len(calls) == 1 and calls[0][-2:] == ["--read", "a b.pcapng"] and not pages


def test_missing_driver_opens_official_installer_page(monkeypatch):
    pages = []
    monkeypatch.setattr(bootstrap, "prepare", lambda: "python.exe")
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1))
    monkeypatch.setattr(bootstrap.webbrowser, "open", pages.append)
    assert bootstrap.main([]) == 1
    assert pages == ["https://npcap.com/#download"]


def test_existing_old_venv_is_upgraded_before_install(tmp_path, monkeypatch):
    python = tmp_path / ".venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.touch()
    (tmp_path / "requirements.txt").write_text("scapy\npsutil\n")
    calls = []
    def invoke(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1 if len(calls) == 1 else 0)
    monkeypatch.setattr(bootstrap.subprocess, "run", invoke)
    bootstrap.prepare(tmp_path)
    assert "--upgrade" in calls[1]
    assert "pip" in calls[-1]
