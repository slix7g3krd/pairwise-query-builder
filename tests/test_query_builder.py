import pytest

from security.query_builder import (
    quote_identifier,
    escape_like,
    build_query,
    validate_order,
    is_multi_statement
)


def test_ident_ok():
    assert quote_identifier('name', {'name'}) == 'name'

def test_ident_bad():
    assert quote_identifier('name;drop', {'name'}) is None

def test_order_ok():
    assert validate_order('name', {'name'}) is True

def test_order_bad():
    assert validate_order('name; drop', {'name'}) is False

def test_like_percent():
    assert escape_like('100%') == '100' + chr(92) + '%'

def test_like_underscore():
    assert escape_like('a_b') == 'a' + chr(92) + '_b'

def test_params():
    sql, params = build_query('t', ['a'], {'a': 'x'}, 'a', 10, 't1')
    assert '?' in sql
    assert 'x' not in sql

def test_multi():
    assert is_multi_statement('select 1; select 2') is True

def test_single():
    assert is_multi_statement('select 1') is False

def test_limit_cap():
    sql, params = build_query('t', ['a'], {}, 'a', 10**9, 't1')
    assert 'LIMIT 100' in sql

def test_negative():
    import pytest
    with pytest.raises(ValueError):
        build_query('t', ['a'], {}, 'a', -1, 't1')

def test_tenant():
    sql, params = build_query('t', ['a'], {}, 'a', 10, 't1')
    assert 'tenant_id = ?' in sql

def test_column_injection():
    assert quote_identifier('a, b', {'a', 'b'}) is None

def test_union_order():
    assert validate_order('a UNION select 1', {'a'}) is False

def test_empty_table():
    import pytest
    with pytest.raises(ValueError):
        build_query('', ['a'], {}, 'a', 10, 't1')
