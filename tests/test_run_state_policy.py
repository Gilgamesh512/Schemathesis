import pytest

from modules.rest.run_schemathesis1 import RunState as RestRunState
from modules.graphql.run_graphql_fuzz1 import RunState as GraphQLRunState


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_confirmed_state_cannot_be_downgraded(tmp_path, state_class):
    state = state_class(tmp_path / "state.json")
    state.record("fp-1", "confirmed")

    state.record("fp-1", "rejected")

    assert state.status("fp-1") == "confirmed"
    assert state.attempts("fp-1") == 2


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_candidate_is_not_erased_by_rejected_retry(
    tmp_path, state_class
):
    state = state_class(tmp_path / "state.json")
    state.record("fp-1", "candidate")

    state.record("fp-1", "rejected")

    assert state.status("fp-1") == "candidate"
    assert state.attempts("fp-1") == 2


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_candidate_can_be_promoted_to_confirmed(tmp_path, state_class):
    state = state_class(tmp_path / "state.json")
    state.record("fp-1", "candidate")

    state.record("fp-1", "confirmed")

    assert state.status("fp-1") == "confirmed"
    assert state.attempts("fp-1") == 2


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_rejected_can_become_candidate(tmp_path, state_class):
    state = state_class(tmp_path / "state.json")
    state.record("fp-1", "rejected")

    state.record("fp-1", "candidate")

    assert state.status("fp-1") == "candidate"
    assert state.attempts("fp-1") == 2

# --------------------------------------------------------------------------
# ISS-REL-2: Corrupted state recovery and atomic replacement
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_missing_state_initializes_empty(tmp_path, state_class):
    state_file = tmp_path / "state.json"
    assert not state_file.exists()

    state = state_class(state_file)
    assert state.data == {}
    assert state.status("fp-missing") is None
    assert state.attempts("fp-missing") == 0


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_valid_state_loads_and_preserves_all_fields(tmp_path, state_class):
    state_file = tmp_path / "state.json"
    state_file.write_text(
        '{"fp-1": {"attempts": 2, "status": "candidate", "last_seen": "2026-10-25T00:00:00Z", "custom": 123}}',
        encoding="utf-8",
    )

    state = state_class(state_file)
    assert state.status("fp-1") == "candidate"
    assert state.attempts("fp-1") == 2
    assert state.data["fp-1"]["custom"] == 123


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_truncated_or_malformed_json_triggers_quarantine_recovery(tmp_path, state_class, capsys):
    state_file = tmp_path / "state.json"
    state_file.write_text('{"truncated": ', encoding="utf-8")

    state = state_class(state_file)
    assert state.data == {}

    # Warning must be emitted to stderr
    captured = capsys.readouterr().err
    assert "CANH BAO" in captured
    assert "state_corrupted.json" in captured
    assert "File goc da duoc luu tai" in captured

    # Original malformed content must remain available in quarantine file
    quarantine = tmp_path / "state_corrupted.json"
    assert quarantine.exists()
    assert quarantine.read_text(encoding="utf-8") == '{"truncated": '


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_multiple_quarantines_do_not_overwrite_earlier_archives(tmp_path, state_class):
    state_file = tmp_path / "state.json"

    # Pre-existing archive
    existing_archive = tmp_path / "state_corrupted.json"
    existing_archive.write_text('{"first_archive": true}', encoding="utf-8")

    # New corrupted file
    state_file.write_text('{"second_corrupt": true', encoding="utf-8")

    state = state_class(state_file)
    assert state.data == {}

    # First archive is untouched
    assert existing_archive.read_text(encoding="utf-8") == '{"first_archive": true}'

    # Second archive created with suffix
    second_archive = tmp_path / "state_corrupted_2.json"
    assert second_archive.exists()
    assert second_archive.read_text(encoding="utf-8") == '{"second_corrupt": true'


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_atomic_save_replaces_state_and_preserves_valid_json(tmp_path, state_class):
    state_file = tmp_path / "state.json"
    state = state_class(state_file)
    state.record("fp-1", "candidate")
    state.save()

    assert state_file.exists()
    loaded = state_class(state_file)
    assert loaded.status("fp-1") == "candidate"
    assert loaded.attempts("fp-1") == 1

    # Check that no temporary files remain
    tmp_files = list(tmp_path.glob("*.tmp*"))
    assert len(tmp_files) == 0


@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_simulated_save_failure_preserves_original_state(tmp_path, state_class, monkeypatch):
    from pathlib import Path
    state_file = tmp_path / "state.json"
    state = state_class(state_file)
    state.record("fp-original", "candidate")
    state.save()

    original_bytes = state_file.read_bytes()

    # Modify in-memory state without saving yet
    state.data["fp-new"] = {"attempts": 1, "status": "confirmed"}

    def failing_replace(self, target):
        raise OSError("Simulated replacement failure (disk full)")

    monkeypatch.setattr(Path, "replace", failing_replace)

    with pytest.raises(OSError, match="Simulated replacement failure"):
        state.save()

    # Original file must remain intact and untruncated
    assert state_file.read_bytes() == original_bytes

    # Temp files must be cleaned up
    tmp_files = list(tmp_path.glob("*.tmp*"))
    assert len(tmp_files) == 0

@pytest.mark.parametrize(
    "state_class",
    [RestRunState, GraphQLRunState],
)
def test_quarantine_copy_failure_reports_truthful_diagnostic(tmp_path, state_class, capsys, monkeypatch):
    import shutil
    state_file = tmp_path / "state.json"
    state_file.write_text('{"bad_json": ', encoding="utf-8")

    def failing_copy2(src, dst):
        raise OSError("Permission denied / disk full")

    monkeypatch.setattr(shutil, "copy2", failing_copy2)

    state = state_class(state_file)
    assert state.data == {}

    captured = capsys.readouterr().err
    # Must report the copy failure
    assert "Khong the luu ban sao state bi hong" in captured
    # Must truthfully report that archive was NOT created and original file is kept
    assert "Khong the tao ban sao luu tru; file goc van duoc giu nguyen tren dia" in captured
    assert "File goc da duoc luu tai" not in captured

    # Original corrupted file must remain untouched on disk
    assert state_file.exists()
    assert state_file.read_text(encoding="utf-8") == '{"bad_json": '

    # No archive should have been created
    archive = tmp_path / "state_corrupted.json"
    assert not archive.exists()
