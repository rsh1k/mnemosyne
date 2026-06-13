"""NIST / OWASP control-catalog tests.

The catalog is the auditor-facing artifact, so these tests guard its integrity:
unique control IDs, non-empty mappings to each referenced framework, explicit
ASI06 coverage, and a stable serialised shape consumed by the CLI and the
``/v1/compliance`` endpoint.
"""

from __future__ import annotations

from mnemosyne.nist import CONTROL_CATALOG, catalog_as_dicts


def test_catalog_is_nonempty():
    assert len(CONTROL_CATALOG) == 11


def test_control_ids_are_unique():
    ids = [c.control_id for c in CONTROL_CATALOG]
    assert len(ids) == len(set(ids))


def test_every_control_has_owasp_and_implementation():
    for c in CONTROL_CATALOG:
        assert c.owasp, f"{c.control_id} missing OWASP mapping"
        assert c.implemented_by, f"{c.control_id} missing implementation reference"
        assert c.name and c.description


def test_every_control_maps_to_at_least_one_nist_framework():
    for c in CONTROL_CATALOG:
        frameworks = (
            c.nist_80053 + c.nist_ssdf_218a + c.nist_ai_600_1 + c.nist_csf_20
        )
        assert frameworks, f"{c.control_id} maps to no NIST framework"


def test_asi06_is_covered():
    joined = " ".join(o for c in CONTROL_CATALOG for o in c.owasp).lower()
    assert "asi06" in joined


def test_ssdf_and_ai_rmf_present_somewhere():
    all_218a = [x for c in CONTROL_CATALOG for x in c.nist_ssdf_218a]
    all_600 = [x for c in CONTROL_CATALOG for x in c.nist_ai_600_1]
    assert all_218a, "no SP 800-218A (SSDF) references in catalog"
    assert all_600, "no AI 600-1 (AI RMF) references in catalog"


def test_serialised_shape_is_stable():
    dicts = catalog_as_dicts()
    assert len(dicts) == len(CONTROL_CATALOG)
    expected_keys = {
        "control_id",
        "name",
        "description",
        "owasp",
        "nist_sp_800_53",
        "nist_sp_800_218a",
        "nist_ai_600_1",
        "nist_csf_2_0",
        "implemented_by",
    }
    for d in dicts:
        assert expected_keys.issubset(d.keys())
