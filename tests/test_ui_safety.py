import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ui"))
from safe import esc  # noqa: E402


def test_model_text_cannot_inject_html_into_the_ui():
    evil = '<img src=x onerror=alert(1)><script>steal()</script> & "quoted"'
    out = esc(evil)
    assert "<" not in out and ">" not in out
    assert "&lt;script&gt;" in out and "&amp;" in out and "&quot;quoted&quot;" in out
