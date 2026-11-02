# Injected via PYTHONPATH inside the sandbox: measure branch coverage of the skill's own python files.
import os

_d = os.environ.get("SKF_COV_DIR")
if _d:
    try:
        import atexit
        import coverage

        _c = coverage.Coverage(data_file=os.path.join(_d, ".coverage"), data_suffix=True, branch=True,
                               source=[os.environ.get("SKF_SKILL_DIR", "/nonexistent")], config_file=False)
        _c.start()

        def _save():
            try:
                _c.stop()
                _c.save()
            except Exception:
                pass

        atexit.register(_save)
    except Exception:
        pass
