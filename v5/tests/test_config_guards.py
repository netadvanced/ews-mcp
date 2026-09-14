"""Settings guards: absolute data_dir + the synced-folder refusal.

The data dir holds mail-at-rest (aliases, audit chain, cache mirror) —
booting with it inside OneDrive/Dropbox/… replicates a mailbox to every
synced device, so the default posture is refusal with an explicit escape
hatch.
"""

import pytest

from conftest import make_settings


def test_data_dir_is_always_absolute(tmp_path):
    s = make_settings(data_dir=str(tmp_path / "d"))
    import os
    assert os.path.isabs(s.data_dir)


def test_default_data_dir_is_home_scoped_absolute(monkeypatch, tmp_path):
    monkeypatch.delenv("DATA_DIR", raising=False)
    s = make_settings()
    assert s.data_dir.endswith(".ewsmcp")


@pytest.mark.parametrize("marker", ["OneDrive", "Dropbox", "Google Drive"])
def test_synced_paths_are_refused(tmp_path, marker):
    with pytest.raises(Exception, match="synced"):
        make_settings(data_dir=str(tmp_path / marker / "data"))


def test_synced_path_escape_hatch(tmp_path):
    s = make_settings(data_dir=str(tmp_path / "OneDrive" / "data"),
                      data_dir_allow_synced=True)
    assert "OneDrive" in s.data_dir


def test_confirm_ttl_default_matches_confirm_module():
    from ewsmcp import confirm
    assert make_settings().confirm_ttl_seconds == confirm.DEFAULT_TTL_SECONDS == 600


# --- EWS_VERSION_BUILD / EWS_API_VERSION ----------------------------------------


def test_version_pin_is_off_by_default():
    s = make_settings()
    assert s.ews_version_build is None
    assert s.ews_api_version is None


def test_version_pin_accepts_build_and_api_version():
    s = make_settings(ews_version_build=" 15.2.2562.43 ", ews_api_version="Exchange2016")
    assert s.ews_version_build == "15.2.2562.43"
    assert s.ews_api_version == "Exchange2016"


def test_blank_version_values_mean_unset():
    s = make_settings(ews_version_build="", ews_api_version="")
    assert s.ews_version_build is None
    assert s.ews_api_version is None


@pytest.mark.parametrize("build", ["15.2", "15.2.2562", "15.2.2562.43.1", "v15.2.2562.43",
                                   "15.2.x.43", "7.0.0.0"])
def test_malformed_build_is_refused(build):
    with pytest.raises(Exception, match="EWS_VERSION_BUILD.*major.minor.build.revision"):
        make_settings(ews_version_build=build)


def test_api_version_without_build_is_refused():
    with pytest.raises(Exception, match="EWS_API_VERSION only works together with"):
        make_settings(ews_api_version="Exchange2016")


def test_unknown_api_version_is_refused():
    with pytest.raises(Exception, match="not a known EWS API version.*Exchange2016"):
        make_settings(ews_version_build="15.2.2562.43", ews_api_version="Exchange 2016")
