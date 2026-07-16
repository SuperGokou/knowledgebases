from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def test_clamav_database_preflight_requires_daily_and_main_and_uses_sigtool() -> None:
    script = (REPOSITORY / "docker/clamav/preflight-database.sh").read_text(encoding="utf-8")

    assert "main.cvd main.cld" in script
    assert "daily.cvd daily.cld" in script
    assert "444|644" in script
    assert "owner_uid=$(stat -c '%u'" in script
    assert "must be owned by root" in script
    assert "test -r" in script
    assert "sha256sum" in script
    assert "sigtool --info" in script
    assert "stat -c" in script
    assert "world-writable" in script


def test_offline_image_manifest_is_generated_and_verified_from_compose() -> None:
    script = (REPOSITORY / "deploy/tencent/verify-offline-images.sh").read_text(encoding="utf-8")

    assert "config --images" in script
    assert "generate" in script
    assert "verify" in script
    assert "docker image inspect" in script
