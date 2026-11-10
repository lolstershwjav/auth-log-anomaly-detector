import pytest
from authguard.detector import detect, read_rows


def row(failed=0, ips=1, off=0, success=5):
    return {"user": "test", "window_start": "2026-01-01T00:00:00Z", "features": [failed, ips, off, success]}


def test_detect_returns_scores_and_flags_outlier():
    baseline = [row(i % 3, 1 + i % 2, i % 2, 3 + i % 5) for i in range(40)]
    result = detect(baseline, [row(1, 1, 0, 4), row(80, 30, 40, 0)])
    assert len(result) == 2
    assert result[1]["anomaly"] is True
    assert isinstance(result[1]["score"], float)


def test_minimum_baseline():
    with pytest.raises(ValueError, match="10 baseline"):
        detect([row()], [row()])


def test_invalid_contamination():
    with pytest.raises(ValueError, match="contamination"):
        detect([row()] * 10, [row()], 0)


def test_read_rows_rejects_negative_counts(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("user,window_start,failed_logins,unique_ips,off_hours_logins,successful_logins\na,now,-1,1,0,0\n")
    with pytest.raises(ValueError, match="nonnegative"):
        read_rows(p)


def test_read_rows_missing_column(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("user,failed_logins\na,2\n")
    with pytest.raises(ValueError, match="Missing columns"):
        read_rows(p)
