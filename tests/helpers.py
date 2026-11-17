import tempfile
from soc.config import Workspace
from soc import simulator, pipeline


def fresh_run(level=None):
    ws = Workspace(tempfile.mkdtemp(prefix="soc_test_"))
    simulator.generate(ws)
    pipeline.run(ws, level, log=lambda *_: None)
    return ws
