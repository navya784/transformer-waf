from waf.generate_dataset import make_rows
from waf.preprocess import normalize, request_to_text


def test_normalize_decodes_double_encoding():
    assert normalize("%253Cscript%253E") == "<script>"


def test_normalize_strips_sql_comments():
    assert normalize("1/**/UNION/**/SELECT") == "1 UNION SELECT"


def test_request_to_text_format():
    t = request_to_text("get", "/search", "q=%27+OR+1%3D1", "")
    assert t.startswith("[METHOD] GET [PATH] /search [QUERY] q=' OR 1=1")


def test_dataset_has_all_classes():
    df = make_rows(600, seed=1)
    assert set(df.label) == {0, 1, 2}
    assert df.text.is_unique
