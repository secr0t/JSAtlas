"""稳定 ID 规则测试：确定性是这套模型的地基，必须先钉死。"""

from jsatlas.models import ids


def test_source_id_is_content_derived():
    a = ids.source_id("sha256-abc", "some/file.js")
    b = ids.source_id("sha256-abc", "some/file.js")
    c = ids.source_id("sha256-xyz", "some/file.js")
    assert a == b
    assert a != c
    assert a.startswith("src_")


def test_id_prefixes():
    assert ids.surface_id("src_1", "api_path", "/a").startswith("srf_")
    assert ids.point_id("src_1", "srf_1", "query", "page").startswith("pnt_")
    assert ids.intelligence_id("src_1", "credential", "jwt", "eyJ").startswith("itl_")
    assert ids.relationship_id("api_has_param", "srf_1", "pnt_1").startswith("rel_")
    assert ids.evidence_id("src_1", "analyzer", 0, 10, "basis").startswith("evd_")


def test_id_length_is_fixed():
    """固定长度，避免下游按长度做假设时踩坑。"""
    for value in (
        ids.source_id("x"),
        ids.surface_id("src_1", "api_path", "/a"),
        ids.point_id("src_1", "", "query", "p"),
    ):
        assert len(value) == 4 + 12


def test_same_semantics_same_id():
    """语义相同必须收敛到同一 ID —— 这是去重能生效的前提。"""
    assert ids.surface_id("src_1", "api_path", "/api/user") == \
        ids.surface_id("src_1", "api_path", "/api/user")
    assert ids.surface_id("src_1", "api_path", "/api/user", "POST") != \
        ids.surface_id("src_1", "api_path", "/api/user", "GET")


def test_different_source_different_id():
    """同源判定不能跨资源串味。"""
    assert ids.surface_id("src_1", "api_path", "/api/user") != \
        ids.surface_id("src_2", "api_path", "/api/user")


def test_point_without_surface_is_distinct():
    """归属不明（空 surface）不能和已归属的撞 ID。"""
    assert ids.point_id("src_1", "", "body", "name") != \
        ids.point_id("src_1", "srf_1", "body", "name")
