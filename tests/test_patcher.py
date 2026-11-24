"""v1 migration: unsafe direct writes must not remain as an alternate path."""
import pytest

from scriptsentinel.patcher import Patcher, PatchResult


def test_legacy_writer_is_retired_without_file_changes(tmp_path):
    target = tmp_path / "index.html"
    target.write_text("<html>original</html>", encoding="utf-8")
    with pytest.raises(RuntimeError, match="retired in v1"):
        Patcher(base_url="https://example.invalid")
    assert target.read_text(encoding="utf-8") == "<html>original</html>"
    assert not list(tmp_path.glob("*.bak"))


def test_patch_result_compatibility():
    result = PatchResult("index.html", True, "original.bak", 1, False, "approved SRI")
    assert result.to_dict()["scripts_patched"] == 1
