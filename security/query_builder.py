"""安全报表查询构造器。

修复清单（对应 README 中 15 项）：
1.  标识符白名单           -- quote_identifier / _validate_identifier
2.  ORDER/GROUP 白名单     -- validate_order（GROUP BY 复用同一校验）
3.  LIKE 转义              -- escape_like，配合 ``ESCAPE '\\'``
4.  禁用多语句             -- is_multi_statement，执行前强制检查
5.  全部参数化             -- WHERE 值走占位符；LIMIT/OFFSET 经严格整数校验后内联
6.  错误脱敏               -- sanitize_error / 自定义异常只暴露安全信息
7.  租户条件强制           -- tenant_id 缺失即报错，SQL 恒含 tenant_id 过滤
8.  分页边界               -- 负数报错，上限 MAX_LIMIT 截断
9.  语句独立               -- execute_query 每次新建游标，杜绝预处理复用参数残留
10. 错误分类               -- QueryBuilderError 异常体系
11. NULL 语义              -- None -> IS NULL，空串 -> = ?，二者不再混淆
12. 编码统一               -- 一律 UTF-8 严格解码，失败抛 EncodingError
13. 超时                   -- DEFAULT_QUERY_TIMEOUT_MS + sqlite progress handler
14. 行数上限               -- MAX_LIMIT / MAX_ROWS，超出抛 RowLimitExceeded
15. 日志脱敏               -- redact_sql + RedactingFilter，参数绝不落日志
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

#: 合法标识符：字母/下划线开头，仅含字母数字下划线，最长 64
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

#: 排序方向白名单
_DIRECTIONS = frozenset({"ASC", "DESC"})

#: 任何用户可控标识符片段中都不允许出现的危险 token
_FORBIDDEN_PATTERNS = re.compile(
    r"(--|/\*|\*/|;|`|\"|'|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|"
    r"\bDELETE\b|\bDROP\b|\bALTER\b|\bCREATE\b|\bEXEC\b|\bxp_)",
    re.IGNORECASE,
)

#: 分页硬上限，防止导出全表
MAX_LIMIT = 100

#: 单次执行允许取回的最大行数
MAX_ROWS = 100

#: 语句默认超时（毫秒）
DEFAULT_QUERY_TIMEOUT_MS = 5_000

#: LIKE 通配符转义符
LIKE_ESCAPE = "\\"

#: 占位符（ANSI 风格，sqlite3 以 ``?`` 为参数占位符）
PLACEHOLDER = "?"

logger = logging.getLogger("security.query_builder")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# 10. 错误分类：自定义异常体系
# ---------------------------------------------------------------------------

class QueryBuilderError(ValueError):
    """所有查询构造/执行错误的基类（继承 ValueError 兼容调用方校验）。

    :param safe_message: 可安全回显给前端的信息，不含表名/列名/SQL。
    :param details: 仅用于服务端排查的内部细节，不会出现在 ``str(e)`` 中。
    """

    def __init__(self, safe_message: str, details: Optional[str] = None):
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.details = details

    def __str__(self) -> str:  # 绝不泄露 details
        return self.safe_message


class IdentifierError(QueryBuilderError):
    """标识符不在白名单或格式非法。"""


class OrderByError(QueryBuilderError):
    """ORDER BY / GROUP BY 字段不在白名单或含非法结构。"""


class MultiStatementError(QueryBuilderError):
    """检测到堆叠多语句。"""


class PaginationError(QueryBuilderError):
    """LIMIT/OFFSET 非法（负数、非整数等）。"""


class TenantFilterError(QueryBuilderError):
    """缺少租户隔离条件。"""


class EncodingError(QueryBuilderError):
    """输入不是合法 UTF-8。"""


class QueryTimeoutError(QueryBuilderError):
    """查询执行超时。"""


class RowLimitExceeded(QueryBuilderError):
    """结果集行数超过上限。"""


# ---------------------------------------------------------------------------
# 12. 编码统一：入口处全部转成 UTF-8 文本
# ---------------------------------------------------------------------------

def _to_text(value: Any) -> Any:
    """把 bytes 按 UTF-8 严格解码；str 原样返回；其他类型交给参数绑定。"""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise EncodingError(
                "输入包含非法编码，仅接受 UTF-8",
                details=f"utf-8 decode failed at byte {exc.start}",
            )
    if isinstance(value, str):
        # 拒绝代理项等畸形 Unicode，避免下游编码不一致导致引号逃逸
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise EncodingError(
                "输入包含非法编码，仅接受 UTF-8",
                details=f"surrogate/illegal unicode at index {exc.start}",
            )
    return value


# ---------------------------------------------------------------------------
# 1. 标识符白名单
# ---------------------------------------------------------------------------

def quote_identifier(name: Any, allowed: Iterable[str]) -> Optional[str]:
    """校验标识符是否在白名单内。

    合法则原样返回标识符（调用方给定的白名单本身即受信来源，无需再加引号）；
    任何格式非法、不在白名单内的输入一律返回 ``None``，绝不抛拼接结果。
    """
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or not _IDENT_RE.match(name):
        return None
    allowed_set = set(allowed) if allowed is not None else set()
    if name not in allowed_set:
        return None
    return name


def _validate_identifier(name: Any, allowed: Iterable[str], kind: str) -> str:
    """quote_identifier 的抛异常版本，供 build_query 内部使用。"""
    resolved = quote_identifier(name, allowed)
    if resolved is None:
        raise IdentifierError(
            f"非法的{kind}标识",
            details=f"rejected {kind} identifier: {name!r}",
        )
    return resolved


# ---------------------------------------------------------------------------
# 2. ORDER BY / GROUP BY 白名单
# ---------------------------------------------------------------------------

def validate_order(order: Any, allowed_columns: Iterable[str]) -> bool:
    """校验 ORDER BY/GROUP BY 表达式。

    仅允许“白名单列 [ASC|DESC]”的逗号分隔列表；
    注释、分号、UNION、括号、引号、表达式一律拒绝。
    """
    if order is None:
        return True
    if not isinstance(order, str):
        return False
    text = order.strip()
    if not text:
        return False
    # 堆叠注释/UNION/多语句等直接否决
    if _FORBIDDEN_PATTERNS.search(text):
        return False
    if "(" in text or ")" in text or "[" in text or "]" in text:
        return False

    allowed = set(allowed_columns) if allowed_columns is not None else set()
    for part in text.split(","):
        tokens = part.split()
        if not tokens or len(tokens) > 2:
            return False
        column = tokens[0]
        if not _IDENT_RE.match(column) or column not in allowed:
            return False
        if len(tokens) == 2 and tokens[1].upper() not in _DIRECTIONS:
            return False
    return True


def _require_valid_order(order: Any, allowed: Iterable[str], clause: str) -> str:
    if not validate_order(order, allowed):
        raise OrderByError(
            f"非法的 {clause} 表达式",
            details=f"rejected {clause}: {order!r}",
        )
    return order.strip()


# ---------------------------------------------------------------------------
# 3. LIKE 转义
# ---------------------------------------------------------------------------

def escape_like(pattern: Any) -> str:
    """转义 LIKE 模式中的通配符，使用反斜杠作为 ESCAPE 字符。

    转义顺序：先转义反斜杠本身，再转义 ``%`` 与 ``_``。
    输入统一按 UTF-8 文本处理。
    """
    pattern = _to_text(pattern)
    if not isinstance(pattern, str):
        raise IdentifierError(
            "LIKE 模式必须是字符串",
            details=f"unexpected type {type(pattern).__name__}",
        )
    return (
        pattern.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", LIKE_ESCAPE + "%")
        .replace("_", LIKE_ESCAPE + "_")
    )


class LikePattern:
    """标记一个过滤值应走 LIKE（构造时即完成转义）。"""

    __slots__ = ("raw", "escaped")

    def __init__(self, pattern: Any):
        self.raw = _to_text(pattern)
        if not isinstance(self.raw, str):
            raise IdentifierError(
                "LIKE 模式必须是字符串",
                details=f"unexpected type {type(self.raw).__name__}",
            )
        self.escaped = escape_like(self.raw)


# ---------------------------------------------------------------------------
# 4. 禁用多语句
# ---------------------------------------------------------------------------

def is_multi_statement(sql: Any) -> bool:
    """判断 SQL 是否包含堆叠语句。

    能识别字符串字面量（单/双引号、反引号）与行/块注释内的分号；
    只有出现在字面量/注释之外、且分号后还有实质内容的分号才算多语句，
    语句末尾单个分号不算。
    """
    if not isinstance(sql, str):
        return False
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        # 行注释 -- ...
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            i = sql.find("\n", i)
            if i == -1:
                break
            continue
        # 块注释 /* ... */
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        # 引号内的分号忽略（SQL 中双写引号为转义）
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            while i < n:
                if sql[i] == quote:
                    if i + 1 < n and sql[i + 1] == quote:
                        i += 2
                        continue
                    break
                i += 1
            i += 1
            continue
        if ch == ";":
            tail = sql[i + 1 :].strip()
            if tail:  # 分号后还有内容 => 堆叠语句
                return True
        i += 1
    return False


# ---------------------------------------------------------------------------
# 8. 分页边界
# ---------------------------------------------------------------------------

def _coerce_row_count(value: Any, name: str, default: Optional[int] = None) -> int:
    """严格整数化 LIMIT/OFFSET：拒绝负数、bool、浮点、非数字字符串。"""
    if value is None:
        if default is not None:
            return default
        raise PaginationError(f"缺少 {name} 参数")
    # bool 是 int 的子类，必须显式拒绝
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
            value = int(value.strip())
        else:
            raise PaginationError(
                f"{name} 必须是非负整数",
                details=f"rejected {name}={value!r} ({type(value).__name__})",
            )
    if value < 0:
        raise PaginationError(
            f"{name} 不能为负数",
            details=f"rejected {name}={value!r}",
        )
    return value


# ---------------------------------------------------------------------------
# 6/15. 错误脱敏 & 日志脱敏
# ---------------------------------------------------------------------------

_STRING_LITERAL_RE = re.compile(r"'(?:''|[^'])*'")


def redact_sql(sql: str) -> str:
    """把 SQL 中的字符串字面量替换为占位符，供日志安全记录。"""
    if not isinstance(sql, str):
        return "<unrepresentable sql>"
    return _STRING_LITERAL_RE.sub(PLACEHOLDER, sql)


class RedactingFilter(logging.Filter):
    """日志过滤器：兜底抹掉记录中的字符串字面量。

    对 msg 与每个字符串参数分别脱敏（而非整体丢弃），
    既保证参数值不落日志，又保留日志的结构化骨架。
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_sql(record.msg)
        if isinstance(record.args, dict):
            record.args = {
                k: redact_sql(v) if isinstance(v, str) else v
                for k, v in record.args.items()
            }
        elif isinstance(record.args, tuple):
            record.args = tuple(
                redact_sql(a) if isinstance(a, str) else a for a in record.args
            )
        return True


def sanitize_error(exc: BaseException) -> str:
    """把底层异常转换为不含表名/列名/SQL 的安全提示。"""
    if isinstance(exc, QueryBuilderError):
        return exc.safe_message
    return "查询执行失败，请检查请求参数或联系管理员"


def _log_query(sql: str) -> None:
    """只记录脱敏后的 SQL 结构，参数永不记录。"""
    logger.info("executing query: %s", redact_sql(sql))


# ---------------------------------------------------------------------------
# 5/7/11. 查询构造：全参数化 + 租户强制 + NULL 语义
# ---------------------------------------------------------------------------

def build_query(
    table: Any,
    columns: Sequence[str],
    filters: Optional[Mapping[str, Any]] = None,
    order_by: Any = None,
    limit: Any = None,
    tenant_id: Any = None,
    offset: Any = 0,
    group_by: Any = None,
    like_filters: Optional[Mapping[str, Any]] = None,
    allowed_tables: Optional[Iterable[str]] = None,
    allowed_columns: Optional[Iterable[str]] = None,
) -> tuple[str, list[Any]]:
    """构造安全的分页查询，返回 ``(sql, params)``。

    - 表名/列名/排序/分组全部走白名单；
    - WHERE 值全部以 ``?`` 占位符绑定，LIKE 值先转义；
    - 恒带 ``tenant_id = ?``，租户缺失直接拒绝；
    - ``None`` 渲染为 ``IS NULL``，空串渲染为 ``= ?``，语义明确区分；
    - LIMIT/OFFSET 经严格整数校验并套用 MAX_LIMIT 上限。
    """
    # 7. 租户条件强制：没有租户身份一律拒绝，防止越权导出
    tenant_id = _to_text(tenant_id)
    if tenant_id is None or (isinstance(tenant_id, str) and not tenant_id):
        raise TenantFilterError("缺少租户隔离条件，拒绝构造查询")

    # 1. 表名白名单
    if not isinstance(table, str) or not table.strip():
        raise IdentifierError("非法的表标识", details="empty table name")
    table_allowed = set(allowed_tables) if allowed_tables is not None else {table.strip()}
    table = _validate_identifier(table, table_allowed, "表")

    # 1. 列白名单：默认以调用方声明的 SELECT 列作为允许集合
    if not columns or not isinstance(columns, (list, tuple, set, frozenset)):
        raise IdentifierError("必须至少声明一个查询列", details="empty columns")
    select_cols = [_validate_identifier(c, columns, "列") for c in columns]
    col_allowed = set(allowed_columns) if allowed_columns is not None else set(select_cols)

    params: list[Any] = []
    where: list[str] = []

    # 租户过滤恒为第一个条件，UNION 等拼接无法绕过（本构造器根本不接受原始 SQL 片段）
    where.append(f"tenant_id = {PLACEHOLDER}")
    params.append(tenant_id)

    filters = filters or {}
    if not isinstance(filters, Mapping):
        raise IdentifierError("过滤条件必须是列到值的映射")

    for column, value in filters.items():
        col = _validate_identifier(column, col_allowed, "过滤")
        value = _to_text(value)
        if value is None:
            # 11. NULL 语义：None 只能走 IS NULL
            where.append(f"{col} IS NULL")
        elif isinstance(value, (list, tuple, set, frozenset)):
            values = [_to_text(v) for v in value]
            if not values:
                # 空 IN 列表在 SQL 中非法，直接收敛为恒假
                where.append("1 = 0")
                continue
            placeholders = ", ".join(PLACEHOLDER for _ in values)
            where.append(f"{col} IN ({placeholders})")
            params.extend(values)
        else:
            # 11. 空串与 NULL 区分：空串照常走 = '' 绑定
            where.append(f"{col} = {PLACEHOLDER}")
            params.append(value)

    # 3. LIKE 参数转义后绑定，并声明 ESCAPE 字符
    for column, pattern in (like_filters or {}).items():
        col = _validate_identifier(column, col_allowed, "LIKE")
        like = pattern if isinstance(pattern, LikePattern) else LikePattern(pattern)
        where.append(f"{col} LIKE {PLACEHOLDER} ESCAPE '{LIKE_ESCAPE}'")
        params.append(like.escaped)

    # 2. ORDER/GROUP 白名单
    group_clause = ""
    if group_by is not None:
        group_clause = " GROUP BY " + _require_valid_order(group_by, col_allowed, "GROUP BY")
    order_clause = ""
    if order_by is not None:
        order_clause = " ORDER BY " + _require_valid_order(order_by, col_allowed, "ORDER BY")

    # 8. 分页边界 + 14. 行数上限
    limit_value = _coerce_row_count(limit, "limit", default=MAX_LIMIT)
    if limit_value > MAX_LIMIT:
        limit_value = MAX_LIMIT
    offset_value = _coerce_row_count(offset, "offset", default=0)

    sql = (
        f"SELECT {', '.join(select_cols)} FROM {table} "
        f"WHERE {' AND '.join(where)}"
        f"{group_clause}{order_clause} "
        f"LIMIT {int(limit_value)} OFFSET {int(offset_value)}"
    )

    # 4. 构造结果自检：任何阶段都不允许出现堆叠语句
    if is_multi_statement(sql):
        raise MultiStatementError("检测到多语句，拒绝构造查询")

    _log_query(sql)
    return sql, params


# ---------------------------------------------------------------------------
# 9/13/14. 语句独立执行 + 超时 + 行数上限
# ---------------------------------------------------------------------------

def execute_query(
    connection: Any,
    sql: str,
    params: Sequence[Any] = (),
    timeout_ms: int = DEFAULT_QUERY_TIMEOUT_MS,
    max_rows: int = MAX_ROWS,
) -> list[tuple]:
    """在给定 DB-API 连接上执行查询并返回结果。

    - 每次调用新建游标、用完即关，不做预处理语句复用，杜绝参数残留；
    - 执行前强制多语句检测；
    - 通过 sqlite3 progress handler 实现语句级超时；
    - 最多取回 ``max_rows + 1`` 行以判定是否超上限。
    """
    sql = _to_text(sql)
    if not isinstance(sql, str) or not sql.strip():
        raise QueryBuilderError("非法的查询语句")
    if is_multi_statement(sql):
        raise MultiStatementError(
            "检测到多语句，拒绝执行",
            details=redact_sql(sql),
        )

    timeout_ms = _coerce_row_count(timeout_ms, "timeout_ms")
    max_rows = _coerce_row_count(max_rows, "max_rows")
    if max_rows == 0:
        raise PaginationError("max_rows 必须大于 0")

    module = type(connection).__module__
    cursor = connection.cursor()  # 9. 独立游标，不跨请求复用
    try:
        # 13. 超时：sqlite3 用 progress handler 在执行中按截止时间中断
        if module.startswith("sqlite3") and hasattr(connection, "set_progress_handler"):
            import time

            deadline = time.monotonic() + timeout_ms / 1000.0

            def _handler() -> int:
                return 1 if time.monotonic() >= deadline else 0

            # 每 1000 个虚拟机指令回调一次
            connection.set_progress_handler(_handler, 1000)

        try:
            cursor.execute(sql, tuple(params))
            rows = cursor.fetchmany(max_rows + 1)  # 14. 多取一行探测超限
        except Exception as exc:  # noqa: BLE001 - 统一脱敏分类
            if module.startswith("sqlite3"):
                import sqlite3

                if isinstance(exc, sqlite3.OperationalError) and "interrupted" in str(exc).lower():
                    raise QueryTimeoutError(
                        "查询超时，已终止",
                        details=redact_sql(sql),
                    )
            raise QueryBuilderError(sanitize_error(exc), details=redact_sql(sql)) from exc
        finally:
            if module.startswith("sqlite3") and hasattr(connection, "set_progress_handler"):
                connection.set_progress_handler(None, 0)

        if len(rows) > max_rows:
            raise RowLimitExceeded(
                f"结果集超过 {max_rows} 行上限，请缩小查询范围",
                details=f"fetched >{max_rows} rows",
            )
        return rows
    finally:
        cursor.close()
