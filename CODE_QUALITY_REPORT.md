# 代码质量检查报告

生成时间：2025-10-18
检查范围：`src/gmssl/` 目录下所有 Python 文件

## 📊 总体评估

| 指标 | 状态 | 说明 |
|------|------|------|
| Ruff 检查 | ✅ 通过 | 所有检查通过 |
| 函数长度 | ✅ 良好 | 仅1个函数>50行 |
| 代码重复 | ⚠️ 需改进 | 发现多处重复模式 |
| 错误处理 | ⚠️ 需改进 | 不一致的错误处理 |
| 类型注解 | ❌ 缺失 | 所有函数缺少类型注解 |
| 文档字符串 | ✅ 良好 | 大部分函数有文档 |

## 🔍 发现的问题

### 1. 重复代码模式（高优先级）

#### 问题 1.1: PEM 工具函数重复
**位置**: `src/gmssl/_pem_utils.py` (行 442-542)

**问题描述**:
四个函数有几乎相同的结构，只是参数和调用的函数名不同：
- `pem_export_encrypted_key`
- `pem_import_encrypted_key`
- `pem_export_public_key`
- `pem_import_public_key`

**重复代码量**: ~100 行

**建议方案**:
```python
def _call_platform_specific_pem_function(
    func_name: str,
    key,
    path: str,
    *args,
    file_mode: str = "rb"
):
    """
    Generic wrapper for platform-specific PEM operations.

    Args:
        func_name: Base function name (e.g., "sm2_public_key_info_to_pem")
        key: Key object
        path: File path
        *args: Additional arguments (e.g., password)
        file_mode: File mode for non-Windows platforms
    """
    if sys.platform == "win32":
        windows_func = globals()[f"{func_name}_windows"]
        windows_func(key, path, *args)
    else:
        with open_file(path, file_mode) as fp:
            gmssl_func = getattr(gmssl, func_name)
            if gmssl_func(byref(key), *args, fp) != 1:
                raise NativeError(f"{func_name} failed")
```

**影响**: 可减少约 80 行重复代码

---

#### 问题 1.2: 错误处理模式不一致
**统计**:
- `"libgmssl inner error"` 出现 56 次
- `if ... != 1:` 模式出现 39 次

**问题描述**:
代码库中已有 `raise_on_error` 辅助函数，但很多地方没有使用：

```python
# 当前代码（重复模式）
if gmssl.sm4_cbc_encrypt_init(byref(self), key, iv) != 1:
    raise NativeError("libgmssl inner error")

# 应该使用
raise_on_error(
    gmssl.sm4_cbc_encrypt_init(byref(self), key, iv),
    "sm4_cbc_encrypt_init"
)
```

**建议**:
1. 统一使用 `raise_on_error` 函数
2. 提供更具体的错误消息（包含函数名）

**影响**: 可提高错误消息的一致性和可调试性

---

#### 问题 1.3: 验证逻辑重复
**统计**: 19 处类似的长度/大小验证

**问题描述**:
```python
# 在多个类中重复
if len(key) != SM4_KEY_SIZE:
    raise ValueError("Invalid key length")

if len(iv) != SM4_BLOCK_SIZE:
    raise ValueError("Invalid IV size")
```

**建议方案**:
```python
def validate_length(data: bytes, expected: int, name: str) -> None:
    """Validate data length matches expected size."""
    if len(data) != expected:
        raise ValueError(
            f"Invalid {name} length: expected {expected}, got {len(data)}"
        )

# 使用
validate_length(key, SM4_KEY_SIZE, "key")
validate_length(iv, SM4_BLOCK_SIZE, "IV")
```

**影响**: 提高验证逻辑的一致性和错误消息质量

---

### 2. 缺少类型注解（中优先级）

**问题描述**:
所有函数都缺少类型注解，这在现代 Python 开发中是不好的实践。

**示例**:
```python
# 当前
def rand_bytes(size):
    """Generate random bytes."""
    ...

# 建议
def rand_bytes(size: int) -> bytes:
    """Generate random bytes."""
    ...
```

**建议**:
1. 为所有公共 API 添加类型注解
2. 为内部函数添加类型注解（可选但推荐）
3. 使用 `mypy` 进行类型检查

**影响**:
- 提高代码可维护性
- 更好的 IDE 支持
- 减少类型相关的 bug

---

### 3. 魔法字符串和常量（低优先级）

**问题描述**:
一些字符串在代码中重复出现：

```python
# 文件模式
"rb", "wb"  # 多处使用

# 错误消息
"libgmssl inner error"  # 56 次
"Invalid key length"  # 多次
```

**建议**:
```python
# 在 _constants.py 中添加
FILE_MODE_READ_BINARY = "rb"
FILE_MODE_WRITE_BINARY = "wb"
ERROR_MSG_NATIVE = "Native library error"
```

**影响**: 提高代码可维护性

---

## 📈 改进建议优先级

### 🔴 高优先级（建议立即处理）

1. **重构 PEM 工具函数** (问题 1.1)
   - 影响：减少 ~80 行重复代码
   - 难度：中等
   - 预计时间：1-2 小时

2. **统一错误处理** (问题 1.2)
   - 影响：提高代码一致性和可调试性
   - 难度：低
   - 预计时间：2-3 小时

### 🟡 中优先级（建议近期处理）

3. **提取验证逻辑** (问题 1.3)
   - 影响：提高验证一致性
   - 难度：低
   - 预计时间：1 小时

4. **添加类型注解** (问题 2)
   - 影响：提高代码质量和可维护性
   - 难度：中等
   - 预计时间：4-6 小时

### 🟢 低优先级（可选）

5. **提取魔法字符串** (问题 3)
   - 影响：小幅提高可维护性
   - 难度：低
   - 预计时间：30 分钟

---

## ✅ 已完成的改进

1. ✅ **重构库加载逻辑** (`_lib.py`)
   - 消除了 ~40 行重复代码
   - 减少嵌套层次从 4 层到 2 层
   - 提取了平台检测逻辑
   - 添加了常量定义

---

## 🎯 下一步行动

建议按以下顺序进行改进：

1. **第一阶段**（本周）
   - [ ] 重构 PEM 工具函数
   - [ ] 统一错误处理模式

2. **第二阶段**（下周）
   - [ ] 提取验证逻辑
   - [ ] 为公共 API 添加类型注解

3. **第三阶段**（可选）
   - [ ] 为内部函数添加类型注解
   - [ ] 提取魔法字符串
   - [ ] 配置 mypy 类型检查

---

## 📝 备注

- 所有改进都应保持向后兼容
- 每次改进后运行完整测试套件
- 遵循项目的 Conventional Commits 规范
- 使用 pre-commit hooks 确保代码质量
