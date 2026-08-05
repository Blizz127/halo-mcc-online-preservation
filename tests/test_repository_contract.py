from pathlib import Path


def test_required_phase_zero_documents_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    required = {
        root / "docs" / "STATUS.md",
        root / "docs" / "ROADMAP.md",
        root / "docs" / "CAPTURE_MATRIX.md",
        root / "docs" / "ARCHITECTURE_HYPOTHESES.md",
        root / "docs" / "EVIDENCE_POLICY.md",
        root / "docs" / "LEGAL_AND_SAFETY.md",
        root / "docs" / "MODEL_ROUTING.md",
    }
    missing = sorted(str(path.relative_to(root)) for path in required if not path.is_file())
    assert not missing, f"missing required Phase 0 documents: {missing}"
