# Delete Domain 功能说明

## 概述

`delete_domain.py` 实现了删除域名记录的功能，支持删除动态域名（GMap）和静态域名（RRS）记录。

## 关键实现

### 1. delete_gmap_record - 删除动态域名记录

用于删除动态域名解析记录（GMap）。

```python
def delete_gmap_record(
    req: DeleteGMapRequest, 
    verify_ssl: bool = False, 
    auth: tuple = ("admin", "Admin@123")
) -> requests.Response
```

**请求格式：**
- 使用 HTTP DELETE 方法
- URL: `https://{host}:20120/views/ADD/dzone/{zone}/gmap`
- Body: JSON 格式，包含 name 和 type

### 2. delete_rrs_record - 删除静态域名记录

用于删除静态域名解析记录（RRS）。

**重要特性：** Body 需要组合为字符串格式 `"name type"`

```python
def delete_rrs_record(
    req: DeleteRrsRequest,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123")
) -> requests.Response
```

**请求格式：**
- 使用 HTTP DELETE 方法
- URL: `https://{host}:20120/views/{view}/zones/{zone}/rrs`
- **Body: 纯字符串格式 `"name type"`** （不是 JSON）
- 示例：`"www.test.com. A"` 或 `"example.com. AAAA"`

### 3. delete_domain - 主函数

根据域名类型（dynamic 或 static）调用相应的删除函数。

## 使用方法

### 动态域名删除示例

```json
{
    "device_info": {
        "management_ip": "10.1.114.14",
        "username": "admin",
        "password": "Admin@123"
    },
    "operation": "delete_domain",
    "data": {
        "name": "ccc.test.com",
        "type": "dynamic",
        "records": ["A", "AAAA"]
    }
}
```

命令行执行：
```bash
python3 domain/delete_domain.py domain/delete_domain_dynamic.json
```

### 静态域名删除示例

```json
{
    "device_info": {
        "management_ip": "10.1.114.14",
        "username": "admin",
        "password": "Admin@123"
    },
    "operation": "delete_domain",
    "data": {
        "name": "example.test.com",
        "type": "static",
        "records": [
            {
                "name": "www",
                "type": "A"
            },
            {
                "name": "@",
                "type": "A"
            }
        ]
    }
}
```

命令行执行：
```bash
python3 domain/delete_domain.py domain/delete_domain_static.json
```

## 输入参数说明

### DeviceInfo (设备信息)
- `management_ip`: 管理节点 IP 地址
- `username`: 用户名
- `password`: 密码

### DynamicDomainInfo (动态域名信息)
- `name`: 域名（如 `ccc.test.com`）
- `type`: 固定为 `"dynamic"`
- `records`: 记录类型列表（如 `["A", "AAAA"]`）

### StaticDomainInfo (静态域名信息)
- `name`: 域名（如 `example.test.com`）
- `type`: 固定为 `"static"`
- `records`: 记录列表，每个记录包含：
  - `name`: 记录名称（如 `"www"` 或 `"@"`）
  - `type`: 记录类型（如 `"A"`, `"AAAA"`, `"CNAME"` 等）

## 返回值

```python
{
    "success": bool,              # 操作是否成功
    "result": {                   # 原始输入数据
        "name": str,
        "type": str,
        ...
    },
    "message": [                  # 操作结果消息列表
        "ccc.test.com. A: 200 - OK",
        "ccc.test.com. AAAA: 200 - OK"
    ]
}
```

## 技术细节

### delete_rrs_record 的特殊处理

与其他 API 不同，`delete_rrs_record` 的 body 必须是组合字符串而不是 JSON：

```python
# 组合字符串: "name type"
name_value = payload.get("name", "")
type_value = payload.get("type", "")
body_string = f"{name_value} {type_value}"

# 使用 data 参数而不是 json 参数
response = requests.delete(
    url, headers=headers, data=body_string, verify=verify_ssl, auth=auth
)
```

### 日志记录

代码包含详细的日志记录，可以通过环境变量 `AUTOZDNS_LOG_LEVEL` 控制日志级别：

```bash
export AUTOZDNS_LOG_LEVEL=DEBUG
python3 domain/delete_domain.py domain/delete_domain.json
```

## 错误处理

代码包含完整的错误处理：
- Pydantic 数据验证错误
- HTTP 请求异常
- 值错误

所有错误都会在返回值的 `message` 字段中返回详细信息。
