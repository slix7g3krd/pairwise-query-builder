# pairwise-query-builder

报表导出服务一支持自定义查询，SQL 注入就回来了：字段名直接字符串拼接，标识符没有白名单；ORDER BY 和 GROUP BY 接受用户输入，堆叠注释能截断后续条件；LIKE 参数不转义 % 和 _，能扩大匹配范围；多语句没有禁用，分号后能追加查询；参数化只用在 WHERE，LIMIT/OFFSET 仍拼接；类型强转失败回显完整 SQL；租户过滤条件可以被 UNION 绕过；分页参数为负数时跳过上限；预处理语句复用后参数残留；错误信息把表名和列名带回前端；NULL 和空串处理不一致；编码不一致导致引号逃逸；查询超时没有设置；结果集行数不限制；日志记录完整 SQL 和参数。security/query_builder.py 是核心，tests/test_query_builder.py 15个红。要修的是：标识符白名单；ORDER/GROUP 白名单；LIKE 转义；禁用多语句；全部参数化；错误脱敏；租户条件强制；分页边界；语句独立；错误分类；NULL 语义；编码统一；超时；行数上限；日志脱敏。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
