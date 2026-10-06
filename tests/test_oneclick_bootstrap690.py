from pathlib import Path


def _source() -> str:
    return (Path(__file__).resolve().parents[1] / "ONECLICK_SETUP.py").read_text(encoding="utf-8")


def test_oneclick_installs_dependencies_before_runtime_import():
    src = _source()
    main = src[src.index("def main() -> int:"):]
    dep = main.index("vpy = ensure_venv_and_dependencies()")
    runtime = main.index("ensure_runtime()")
    assert dep < runtime


def test_oneclick_relaunches_under_venv_before_runtime_import():
    src = _source()
    main = src[src.index("def main() -> int:"):]
    dep = main.index("vpy = ensure_venv_and_dependencies()")
    relaunch = main.index("return relaunch_under_venv(vpy)")
    runtime = main.index("ensure_runtime()")
    assert dep < relaunch < runtime, (
        "A fresh bootstrap must restart ONECLICK_SETUP under .venv before "
        "IMPORT_APP_DATA can import cryptography."
    )


def test_oneclick_relaunch_uses_venv_python_and_guard_marker():
    src = _source()
    helper = src[src.index("def relaunch_under_venv"):src.index("def install_service")]
    assert "NETWORKAUTOMATION_ONECLICK_VENV_READY" in helper
    assert "subprocess.run([str(vpy), str(Path(__file__).resolve())]" in helper
