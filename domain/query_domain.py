import json
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
import requests
import urllib3
import sys
from typing import List, Dict, Any, Optional, Literal, Tuple
from urllib.parse import quote

from pydantic import BaseModel, Field, ValidationError, ConfigDict, model_validator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)

#############################################################
### 日志配置 ###

LOG_LEVEL = os.getenv("AUTOZDNS_LOG_LEVEL", "INFO").upper()
REQUEST_TIMEOUT = float(os.getenv("AUTOZDNS_REQUEST_TIMEOUT", "15"))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.getenv("AUTOZDNS_LOG_DIR", os.path.join(PROJECT_ROOT, "logs"))
LOG_FILE = os.path.join(
    LOG_DIR,
    f"{os.path.splitext(os.path.basename(__file__))[0]}.log",
)

socket.setdefaulttimeout(REQUEST_TIMEOUT)


def _configure_logger() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    configured_logger = logging.getLogger(
        f"autozdns.{os.path.splitext(os.path.basename(__file__))[0]}"
    )
    configured_logger.handlers.clear()
    configured_logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )

    configured_logger.addHandler(file_handler)
    configured_logger.propagate = False
    return configured_logger


logger = _configure_logger()


def _format_log_value(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except TypeError:
        return str(value)


def _log_step(module: str, message: str, **details: Any) -> None:
    if details:
        detail_text = " ".join(
            f"{key}={_format_log_value(value)}" for key, value in details.items()
        )
        logger.info("[%s] %s | %s", module, message, detail_text)
        return

    logger.info("[%s] %s", module, message)


def _log_exception(module: str, message: str) -> None:
    logger.exception("[%s] %s", module, message)


def _log_http_response(module: str, response: requests.Response) -> None:
    body_preview = response.text[:300].replace("\n", "\\n")
    _log_step(
        module,
        "HTTP 响应",
        status_code=response.status_code,
        content_type=response.headers.get("Content-Type", ""),
        body_preview=body_preview,
    )


def _default_input_path(filename: str) -> str:
    return os.path.join(os.path.dirname(__file__), "input", filename)


def _load_input_data(input_path: str) -> Any:
    with open(input_path, "r", encoding="utf-8") as file:
        return json.load(file)


def _print_cli_result(result: BaseModel) -> None:
    print(result.model_dump_json(indent=2, ensure_ascii=False))


def _print_cli_error(message: str) -> None:
    print(
        json.dumps(
            {
                "success": False,
                "message": [message],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


#############################################################
### 标准输入规范 ###


class DeviceInfoBase(BaseModel):
    management_ip: str = Field(..., description="管理节点 IP")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


class ConditionBase(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    field_name: str = Field(..., alias="field", description="查询字段")
    value: str = Field(..., description="查询值")
    record_type: str = Field(default="", alias="type", description="记录类型")
    match_type: str = Field(default="fuzzy", description="匹配类型，fuzzy 或 exact")

    @model_validator(mode="before")
    @classmethod
    def fill_field_alias(cls, data: Any) -> Any:
        if isinstance(data, dict) and "field" not in data and "filed" in data:
            data = dict(data)
            data["field"] = data["filed"]
        return data

    @model_validator(mode="after")
    def normalize_values(self) -> "ConditionBase":
        self.field_name = self.field_name.strip()
        self.value = self.value.strip()
        self.record_type = self.record_type.strip()
        self.match_type = self.match_type.lower()
        if self.match_type not in {"fuzzy", "exact"}:
            raise ValueError("match_type 仅支持 fuzzy 或 exact")
        if self.field_name == "":
            raise ValueError("field 不能为空")
        return self


class OrderBase(BaseModel):
    order_key: str = Field(..., description="排序字段")
    order_type: str = Field(..., description="排序方向，ASC 或 DESC")

    @model_validator(mode="after")
    def normalize_order_type(self) -> "OrderBase":
        self.order_key = self.order_key.strip()
        self.order_type = self.order_type.upper()
        if self.order_type not in {"ASC", "DESC"}:
            raise ValueError("order_type 仅支持 ASC 或 DESC")
        return self


class QueryDomainRequest(BaseModel):
    device_info: DeviceInfoBase = Field(..., description="设备信息")
    operation: Literal["query_domain"] = Field(..., description="操作类型")
    conditions: List[ConditionBase] = Field(..., description="查询条件列表")
    orders: Optional[OrderBase] = Field(default=None, description="排序规则")

    @model_validator(mode="after")
    def validate_conditions(self) -> "QueryDomainRequest":
        if not self.conditions:
            raise ValueError("conditions 至少需要提供一个查询条件")
        return self


#############################################################
### 标准输出规范 ###


class RecordBase(BaseModel):
    name: str = Field(..., description="记录名称")
    value: Optional[str] = Field(default=None, description="记录值")
    enabled: Optional[bool] = Field(default=None, description="是否启用")
    dc: Optional[str] = Field(default=None, description="数据中心")
    weight: Optional[int] = Field(default=None, description="权重")


class HealthCheckConfig(BaseModel):
    type: str = Field(..., description="健康检查类型,如:tcp,http")
    port: Optional[int] = Field(default=None, description="健康检查端口")


class PoolBase(BaseModel):
    name: str = Field(..., description="地址池名称")
    ratio: Optional[int] = Field(default=None, description="域名到地址池的权重")
    enable: Optional[bool] = Field(default=None, description="地址池是否启用")
    type: Optional[str] = Field(default=None, description="地址池类型")
    records: List[RecordBase] = Field(
        default_factory=list, description="地址池成员列表"
    )
    health_check: Optional[HealthCheckConfig] = Field(
        default=None, description="健康检查配置"
    )
    first_algorithm: Optional[str] = Field(default=None, description="首选算法")
    second_algorithm: Optional[str] = Field(default=None, description="次选算法")


class DomainResultBase(BaseModel):
    name: str = Field(..., description="记录名称")
    type: str = Field(..., description="记录类型")
    algorithm: Optional[str] = Field(default=None, description="负载均衡算法")
    enable: Optional[bool] = Field(default=None, description="是否启用")
    ttl: Optional[int] = Field(default=None, description="TTL")
    records: List[RecordBase] = Field(default_factory=list, description="记录值列表")
    pools: List[PoolBase] = Field(default_factory=list, description="关联的地址池列表")


class QueryDomainResponseBase(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: List[DomainResultBase] = Field(
        default_factory=list, description="返回的域名信息"
    )
    message: List[str] = Field(default_factory=list, description="操作结果消息")


#############################################################
### API: 动态域名区列表查询 ###


def get_dzone_list(
    host: str, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    url = f"https://{host}:20120/views/ADD/dzone"
    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{host}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }

    _log_step("get_dzone_list", "准备发送动态域名区列表查询请求", url=url)

    response = requests.get(
        url,
        headers=headers,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("get_dzone_list", response)
    return response


#############################################################
### API: 动态域名查询 ###


class GMapQueryParams(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图必须是 ADD")
    zone: str = Field(..., description="域名区")
    search_attrs: List[List[str]] = Field(..., description="搜索属性嵌套列表")
    orders: Optional[OrderBase] = Field(default=None, description="排序规则")
    version: int = Field(default=2, description="接口版本")


class GpoolParamsBase(BaseModel):
    host: str = Field(..., description="设备管理IP")
    pool_names: List[str] = Field(..., description="地址池名称列表")
    version: str = Field(default="2", description="API版本")


def _build_dns_search_query(
    search_attrs: List[List[str]],
    orders: Optional[OrderBase] = None,
    version: int = 2,
) -> str:
    query_parts: List[str] = []

    for index, attr_group in enumerate(search_attrs):
        if len(attr_group) < 3:
            continue

        connector = attr_group[3] if len(attr_group) > 3 else "and"
        query_parts.extend(
            [
                f"search_attrs[{index}][0]={quote(str(attr_group[0]), safe='')}",
                f"search_attrs[{index}][1]={quote(str(attr_group[1]), safe='')}",
                f"search_attrs[{index}][2]={quote(str(attr_group[2]), safe='')}",
                f"search_attrs[{index}][3]={quote(str(connector), safe='')}",
            ]
        )

    if orders is not None:
        query_parts.extend(
            [
                f"order_key={quote(str(orders.order_key), safe='')}",
                f"order_type={quote(str(orders.order_type), safe='')}",
            ]
        )

    query_parts.append(f"version={quote(str(version), safe='')}")
    return "&".join(query_parts)


def _build_gpool_query(pool_names: List[str], version: str = "2") -> str:
    query_parts: List[str] = []

    for index, pool_name in enumerate(pool_names):
        connector = "and" if index == len(pool_names) - 1 else "or"
        query_parts.extend(
            [
                f"search_attrs[{index}][0]=name",
                f"search_attrs[{index}][1]=eq",
                f"search_attrs[{index}][2]={quote(str(pool_name), safe='')}",
                f"search_attrs[{index}][3]={connector}",
            ]
        )

    query_parts.append(f"version={quote(str(version), safe='')}")
    return "&".join(query_parts)


def _build_rrs_search_query(search_attrs: List[List[str]]) -> str:
    query_parts: List[str] = []

    for index, attrs in enumerate(search_attrs):
        key = f"search_key[{index}][]"
        for attr in attrs:
            query_parts.append(f"{key}={quote(str(attr), safe='[]')}")

    return "&".join(query_parts)


def get_gmap_record(
    req: GMapQueryParams,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)
    view_value = payload.pop("view", None)
    zone_value = payload.pop("zone", None)

    url = f"https://{host_value}:20120/views/{view_value}/dzone/{zone_value}/gmap"
    query_string = _build_dns_search_query(req.search_attrs, req.orders, req.version)
    request_url = f"{url}?{query_string}"

    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{host_value}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }

    _log_step(
        "get_gmap_record",
        "准备发送动态域名查询请求",
        url=request_url,
        zone=zone_value,
        search_attrs=req.search_attrs,
    )

    response = requests.get(
        request_url,
        headers=headers,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("get_gmap_record", response)
    return response


def get_gpool(
    req: GpoolParamsBase,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)
    pool_names = req.pool_names
    version_value = payload.get("version", "2")

    url = f"https://{host_value}:20120/gpool"
    query_string = _build_gpool_query(pool_names, version_value)
    request_url = f"{url}?{query_string}"

    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{host_value}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }

    _log_step(
        "get_gpool",
        "准备发送关联地址池查询请求",
        url=request_url,
        pool_names=pool_names,
    )

    response = requests.get(
        request_url,
        headers=headers,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("get_gpool", response)
    return response


#############################################################
### API: 静态域名查询 ###

"""https://10.1.114.14:20120/dns-search-resources?search_key[0][]=name&search_key[0][]=eq&search_key[0][]=bbb.haha.com&search_key[0][]=and"""


class RrsQueryParams(BaseModel):
    host: str = Field(..., description="主机 IP")
    search_attrs: List[List[str]] = Field(..., description="搜索属性嵌套列表")


def dns_search_resources(
    req: RrsQueryParams, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)
    search_attrs = payload.get("search_attrs", [])

    url = f"https://{host_value}:20120/dns-search-resources"
    query_string = _build_rrs_search_query(search_attrs)
    request_url = f"{url}?{query_string}"

    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{host_value}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }

    _log_step(
        "dns_search_resources",
        "准备发送静态域名查询请求",
        url=request_url,
        search_attrs=search_attrs,
    )

    response = requests.get(
        request_url,
        headers=headers,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("dns_search_resources", response)
    return response


"""返回值
{
    "resources": [
        {
            "name": "bbb.haha.com.",
            "type": "A",
            "klass": "IN",
            "ttl": 3600,
            "rdata": "2.4.6.8",
            "reverse_name": "com.haha.bbb",
            "is_enable": "yes",
            "row_id": 9,
            "comment": null,
            "audit_status": "",
            "expire_time": "",
            "expire_style": "",
            "create_time": "2026-04-10 14:52:30",
            "expire_is_enable": "no",
            "href": "/views/default/zones/haha.com/rrs/A$9$default$haha.com",
            "id": "A$9$default$haha.com",
            "view_name": "default",
            "zone_name": "haha.com",
            "members": [
                "local.gslb1",
                "local.哈哈"
            ],
            "is_shared": "",
            "apply_user": null
        },
        {
            "name": "bbb.haha.com.",
            "type": "A",
            "klass": "IN",
            "ttl": 3600,
            "rdata": "3.6.9.12",
            "reverse_name": "com.haha.bbb",
            "is_enable": "yes",
            "row_id": 10,
            "comment": null,
            "audit_status": "",
            "expire_time": "",
            "expire_style": "",
            "create_time": "2026-04-10 14:52:30",
            "expire_is_enable": "no",
            "href": "/views/default/zones/haha.com/rrs/A$10$default$haha.com",
            "id": "A$10$default$haha.com",
            "view_name": "default",
            "zone_name": "haha.com",
            "members": [
                "local.gslb1",
                "local.哈哈"
            ],
            "is_shared": "",
            "apply_user": null
        }
    ],
    "page_num": 1,
    "page_size": 30,
    "total_size": 2,
    "display_attrs": {
        "id": "dns-search-resources",
        "user": "admin",
        "res_type": "dns-search-resources",
        "display": "",
        "attrs": [
            {
                "id": "key_1",
                "type": "text",
                "display_name": "备注",
                "component_type": "single_line_text",
                "option_values": ""
            }
        ],
        "private_attrs": {
            "id": "auth-zone-rr",
            "res_type": "auth-zone-rr",
            "module_type": "DNS",
            "attrs": []
        }
    }
}"""


#############################################################
### 查询核心逻辑 ###


def _ensure_fqdn(name: str) -> str:
    return name if name.endswith(".") else f"{name}."


def _build_dynamic_zone_name(name: str) -> str:
    fqdn = _ensure_fqdn(name).rstrip(".")
    labels = fqdn.split(".")
    if len(labels) < 2:
        raise ValueError(f"非法域名: {name}")
    return f"{labels[-2]}.{labels[-1]}."


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_json_resources(
    response: requests.Response, module: str
) -> List[Dict[str, Any]]:
    try:
        response_data = response.json()
    except requests.exceptions.JSONDecodeError as exc:
        raise ValueError(f"{module} 接口返回内容无法解析为 JSON") from exc

    if not isinstance(response_data, dict):
        raise ValueError(f"{module} 接口返回格式异常")

    resources = response_data.get("resources", [])
    if not isinstance(resources, list):
        raise ValueError(f"{module} 接口缺少 resources 列表")

    return [resource for resource in resources if isinstance(resource, dict)]


def _extract_query_scope(conditions: List[ConditionBase]) -> str:
    for condition in conditions:
        if condition.field_name.lower() != "type":
            continue

        scope = condition.value.lower()
        if scope in {"dynamic", "static", "all"}:
            return scope

    return "dynamic"


def _extract_zone(conditions: List[ConditionBase]) -> Optional[str]:
    for condition in conditions:
        if condition.field_name.lower() == "zone" and condition.value != "":
            return _ensure_fqdn(condition.value)

    return None


def _fetch_dynamic_zones(
    device_info: DeviceInfoBase,
) -> Tuple[List[str], Optional[str]]:
    try:
        response = get_dzone_list(
            device_info.management_ip,
            auth=(device_info.username, device_info.password),
        )
    except requests.RequestException as exc:
        _log_exception("query_domain", "查询动态域名区列表失败")
        return [], f"查询动态域名区列表失败: {exc}"

    if not response.ok:
        return [], f"查询动态域名区列表失败，HTTP状态码: {response.status_code}"

    try:
        resources = _parse_json_resources(response, "动态域名区列表查询")
    except ValueError as exc:
        _log_exception("query_domain", "解析动态域名区列表失败")
        return [], str(exc)

    zones = []
    for resource in resources:
        zone_name = str(resource.get("name", "")).strip()
        if zone_name != "":
            zones.append(zone_name)

    return zones, None


def _resolve_target_zones(
    device_info: DeviceInfoBase,
    conditions: List[ConditionBase],
) -> Tuple[List[str], Optional[str]]:
    explicit_zone = _extract_zone(conditions)
    if explicit_zone is not None:
        return [explicit_zone], None

    return _fetch_dynamic_zones(device_info)


def _build_dynamic_search_attrs(conditions: List[ConditionBase]) -> List[List[str]]:
    operator_mapping = {
        "fuzzy": "in",
        "exact": "eq",
    }
    search_attrs: List[List[str]] = []

    for condition in conditions:
        field_name = condition.field_name.lower()
        value = condition.value.strip()
        if value == "":
            continue

        if field_name == "zone":
            continue

        if field_name == "type" and value.lower() in {"dynamic", "static", "all"}:
            continue

        api_value = value
        if field_name == "name" and "." in value:
            api_value = _ensure_fqdn(value)
        elif field_name == "type":
            api_value = value.upper()

        search_attrs.append(
            [
                condition.field_name,
                operator_mapping[condition.match_type],
                api_value,
                "and",
            ]
        )

        if field_name == "name" and condition.record_type.lower() not in {"", "all"}:
            search_attrs.append(["type", "eq", condition.record_type.upper(), "and"])

    if not search_attrs:
        raise ValueError("缺少有效的动态域名查询条件")

    return search_attrs


def _build_static_search_attrs(conditions: List[ConditionBase]) -> List[List[str]]:
    operator_mapping = {
        "fuzzy": "in",
        "exact": "eq",
    }
    search_attrs: List[List[str]] = []

    for condition in conditions:
        field_name = condition.field_name.lower()
        value = condition.value.strip()
        if value == "":
            continue

        if field_name == "type" and value.lower() in {"dynamic", "static", "all"}:
            continue

        api_field_name = condition.field_name
        api_value = value
        if field_name == "name" and "." in value:
            api_value = _ensure_fqdn(value)
        elif field_name == "zone":
            api_field_name = "zone_name"
            api_value = value.rstrip(".")
        elif field_name == "type":
            api_value = value.upper()

        search_attrs.append(
            [
                api_field_name,
                operator_mapping[condition.match_type],
                api_value,
                "and",
            ]
        )

        if field_name == "name" and condition.record_type.lower() not in {"", "all"}:
            search_attrs.append(["type", "eq", condition.record_type.upper(), "and"])

    if not search_attrs:
        raise ValueError("缺少有效的静态域名查询条件")

    return search_attrs


def _matches_domain_condition(
    resource: Dict[str, Any], condition: ConditionBase
) -> bool:
    field_name = condition.field_name.lower()
    value = condition.value.strip()

    if field_name == "zone":
        actual_zone = _build_dynamic_zone_name(str(resource.get("name", "")))
        expected_zone = _ensure_fqdn(value)
        if condition.match_type == "exact":
            return actual_zone == expected_zone
        return expected_zone in actual_zone

    if field_name == "type" and value.lower() in {"dynamic", "static", "all"}:
        return True

    actual_value = str(resource.get(condition.field_name, ""))
    expected_value = value

    if field_name == "name" and "." in expected_value:
        expected_value = _ensure_fqdn(expected_value)
    if field_name == "type":
        actual_value = actual_value.upper()
        expected_value = expected_value.upper()

    if condition.match_type == "exact":
        matched = actual_value == expected_value
    else:
        matched = expected_value in actual_value

    if not matched:
        return False

    if field_name == "name" and condition.record_type.lower() not in {"", "all"}:
        return str(resource.get("type", "")).upper() == condition.record_type.upper()

    return True


def _matches_static_condition(
    resource: Dict[str, Any], condition: ConditionBase
) -> bool:
    field_name = condition.field_name.lower()
    value = condition.value.strip()

    if field_name == "type" and value.lower() in {"dynamic", "static", "all"}:
        return True

    if field_name == "zone":
        actual_zone = str(resource.get("zone_name", "")).strip().rstrip(".")
        expected_zone = value.rstrip(".")
        if condition.match_type == "exact":
            matched = actual_zone == expected_zone
        else:
            matched = expected_zone in actual_zone
    else:
        lookup_field = "is_enable" if field_name == "enable" else condition.field_name
        actual_value = str(resource.get(lookup_field, ""))
        expected_value = value

        if field_name == "name" and "." in expected_value:
            expected_value = _ensure_fqdn(expected_value)
            actual_value = (
                _ensure_fqdn(actual_value) if actual_value != "" else actual_value
            )
        if field_name == "type":
            actual_value = actual_value.upper()
            expected_value = expected_value.upper()

        if condition.match_type == "exact":
            matched = actual_value == expected_value
        else:
            matched = expected_value in actual_value

    if not matched:
        return False

    if field_name == "name" and condition.record_type.lower() not in {"", "all"}:
        return str(resource.get("type", "")).upper() == condition.record_type.upper()

    return True


def _filter_domain_resources(
    resources: List[Dict[str, Any]],
    conditions: List[ConditionBase],
) -> List[Dict[str, Any]]:
    return [
        resource
        for resource in resources
        if all(
            _matches_domain_condition(resource, condition) for condition in conditions
        )
    ]


def _filter_static_resources(
    resources: List[Dict[str, Any]],
    conditions: List[ConditionBase],
) -> List[Dict[str, Any]]:
    return [
        resource
        for resource in resources
        if all(
            _matches_static_condition(resource, condition) for condition in conditions
        )
    ]


def _sort_domain_resources(
    resources: List[Dict[str, Any]],
    orders: Optional[OrderBase],
) -> List[Dict[str, Any]]:
    if orders is None:
        return resources

    reverse = orders.order_type == "DESC"
    return sorted(
        resources,
        key=lambda item: str(item.get(orders.order_key, "")),
        reverse=reverse,
    )


def _get_member_port(members: Any) -> Optional[int]:
    if not isinstance(members, list):
        return None

    for member in members:
        if not isinstance(member, dict):
            continue

        port_value = _safe_int(member.get("port"))
        if port_value is not None:
            return port_value

    return None


def _build_health_check_from_hms(
    hms: Any,
    members: Any = None,
) -> Optional[HealthCheckConfig]:
    if not isinstance(hms, list) or not hms:
        return None

    first_item = str(hms[0]).strip()
    if first_item == "":
        return None

    member_port = _get_member_port(members)
    if "_" not in first_item:
        return HealthCheckConfig(type=first_item, port=member_port)

    check_type, port_text = first_item.split("_", 1)
    port_value = _safe_int(port_text)
    return HealthCheckConfig(type=check_type, port=port_value or member_port)


def _build_pool_records(resource: Dict[str, Any]) -> List[RecordBase]:
    members = resource.get("gmember_list", [])
    records: List[RecordBase] = []

    if not isinstance(members, list):
        return records

    for member in members:
        if not isinstance(member, dict):
            continue

        member_name = str(member.get("gmember_name", "")).strip()
        if member_name == "":
            continue

        member_ip = str(member.get("ip", "")).strip()
        member_port = str(member.get("port", "")).strip()
        if member_ip and member_port:
            member_value = f"{member_ip}:{member_port}"
        elif member_ip:
            member_value = member_ip
        elif member_port:
            member_value = member_port
        else:
            member_value = None

        member_enable = str(member.get("enable", "")).lower()
        member_enabled: Optional[bool] = None
        if member_enable in {"yes", "no"}:
            member_enabled = member_enable == "yes"

        records.append(
            RecordBase(
                name=member_name,
                value=member_value,
                enabled=member_enabled,
                dc=str(member.get("dc_name", "")).strip() or None,
                weight=_safe_int(member.get("ratio")),
            )
        )

    return records


def _build_pool_base(
    pool_name: str,
    ratio: Optional[int],
    resource: Optional[Dict[str, Any]],
) -> PoolBase:
    if resource is None:
        return PoolBase(name=pool_name, ratio=ratio)

    members = resource.get("gmember_list", [])
    return PoolBase(
        name=pool_name,
        ratio=ratio,
        enable=str(resource.get("enable", "no")).lower() == "yes",
        type=str(resource.get("type", "")).strip() or None,
        records=_build_pool_records(resource),
        health_check=_build_health_check_from_hms(resource.get("hms", []), members),
        first_algorithm=str(resource.get("first_algorithm", "")).strip() or None,
        second_algorithm=str(resource.get("second_algorithm", "")).strip() or None,
    )


def _build_pool_map(resources: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    pool_map: Dict[str, Dict[str, Any]] = {}
    for resource in resources:
        pool_name = str(resource.get("name", "")).strip()
        if pool_name != "":
            pool_map[pool_name] = resource
    return pool_map


def _collect_pool_names(resources: List[Dict[str, Any]]) -> List[str]:
    collected: List[str] = []
    seen = set()

    for resource in resources:
        gpool_list = resource.get("gpool_list", [])
        if not isinstance(gpool_list, list):
            continue

        for item in gpool_list:
            if not isinstance(item, dict):
                continue

            pool_name = str(item.get("gpool_name", "")).strip()
            if pool_name == "" or pool_name in seen:
                continue

            seen.add(pool_name)
            collected.append(pool_name)

    return collected


def _query_related_pools(
    device_info: DeviceInfoBase,
    pool_names: List[str],
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    if not pool_names:
        return {}, []

    try:
        response = get_gpool(
            GpoolParamsBase(
                host=device_info.management_ip,
                pool_names=pool_names,
            ),
            auth=(device_info.username, device_info.password),
        )
    except requests.RequestException as exc:
        _log_exception("query_domain", "查询关联地址池失败")
        return {}, [f"查询关联地址池失败: {exc}"]

    if not response.ok:
        return {}, [f"查询关联地址池失败，HTTP状态码: {response.status_code}"]

    try:
        resources = _parse_json_resources(response, "地址池查询")
    except ValueError as exc:
        _log_exception("query_domain", "解析关联地址池失败")
        return {}, [str(exc)]

    return _build_pool_map(resources), []


def _build_domain_result(
    resource: Dict[str, Any],
    pool_map: Dict[str, Dict[str, Any]],
) -> DomainResultBase:
    pools: List[PoolBase] = []
    gpool_list = resource.get("gpool_list", [])

    if isinstance(gpool_list, list):
        for item in gpool_list:
            if not isinstance(item, dict):
                continue

            pool_name = str(item.get("gpool_name", "")).strip()
            if pool_name == "":
                continue

            pools.append(
                _build_pool_base(
                    pool_name=pool_name,
                    ratio=_safe_int(item.get("ratio")),
                    resource=pool_map.get(pool_name),
                )
            )

    return DomainResultBase(
        name=str(resource.get("name", "")),
        type=str(resource.get("type", "")),
        algorithm=str(resource.get("algorithm", "")).strip() or None,
        enable=(
            str(resource.get("enable", "")).lower() == "yes"
            if str(resource.get("enable", "")).lower() in {"yes", "no"}
            else None
        ),
        ttl=_safe_int(resource.get("ttl")),
        records=[],
        pools=pools,
    )


def _query_dynamic_domain_results(
    request_data: QueryDomainRequest,
) -> Tuple[List[DomainResultBase], List[str], Optional[str]]:
    target_zones, zone_error = _resolve_target_zones(
        request_data.device_info,
        request_data.conditions,
    )
    if zone_error is not None:
        return [], [], zone_error
    if not target_zones:
        return [], [], "未获取到可查询的动态域名区"

    try:
        search_attrs = _build_dynamic_search_attrs(request_data.conditions)
    except ValueError as exc:
        return [], [], str(exc)

    resources: List[Dict[str, Any]] = []
    seen_resource_ids = set()
    for zone_name in target_zones:
        try:
            response = get_gmap_record(
                GMapQueryParams(
                    host=request_data.device_info.management_ip,
                    zone=zone_name,
                    search_attrs=search_attrs,
                    orders=request_data.orders,
                ),
                auth=(
                    request_data.device_info.username,
                    request_data.device_info.password,
                ),
            )
        except requests.RequestException as exc:
            _log_exception("query_domain", "查询动态域名请求失败")
            return [], [], f"查询动态域名请求失败: {exc}"

        if not response.ok:
            return (
                [],
                [],
                f"查询动态域名失败，zone={zone_name}，HTTP状态码: {response.status_code}",
            )

        try:
            zone_resources = _parse_json_resources(response, "动态域名查询")
        except ValueError as exc:
            _log_exception("query_domain", "解析动态域名结果失败")
            return [], [], str(exc)

        for resource in zone_resources:
            resource_id = str(resource.get("id", "")).strip()
            if resource_id != "" and resource_id in seen_resource_ids:
                continue
            if resource_id != "":
                seen_resource_ids.add(resource_id)
            resources.append(resource)

    resources = _filter_domain_resources(resources, request_data.conditions)
    resources = _sort_domain_resources(resources, request_data.orders)

    pool_names = _collect_pool_names(resources)
    pool_map, pool_messages = _query_related_pools(request_data.device_info, pool_names)
    result = [_build_domain_result(resource, pool_map) for resource in resources]
    return result, pool_messages, None


def _query_static_domain_results(
    request_data: QueryDomainRequest,
) -> Tuple[List[DomainResultBase], List[str], Optional[str]]:
    try:
        search_attrs = _build_static_search_attrs(request_data.conditions)
    except ValueError as exc:
        return [], [], str(exc)

    try:
        response = dns_search_resources(
            RrsQueryParams(
                host=request_data.device_info.management_ip,
                search_attrs=search_attrs,
            ),
            auth=(
                request_data.device_info.username,
                request_data.device_info.password,
            ),
        )
    except requests.RequestException as exc:
        _log_exception("query_domain", "查询静态域名请求失败")
        return [], [], f"查询静态域名请求失败: {exc}"

    if not response.ok:
        return [], [], f"查询静态域名失败，HTTP状态码: {response.status_code}"

    try:
        resources = _parse_json_resources(response, "静态域名查询")
    except ValueError as exc:
        _log_exception("query_domain", "解析静态域名结果失败")
        return [], [], str(exc)

    resources = _filter_static_resources(resources, request_data.conditions)
    resources = _sort_domain_resources(resources, request_data.orders)
    result = _build_static_domain_results(resources)
    return _sort_domain_results(result, request_data.orders), [], None


def _build_static_record(resource: Dict[str, Any]) -> RecordBase:
    rdata = resource.get("rdata")
    if isinstance(rdata, list):
        value = " ".join(str(item) for item in rdata)
    elif rdata in (None, ""):
        value = None
    else:
        value = str(rdata)

    is_enable = str(resource.get("is_enable", "")).lower()
    enabled: Optional[bool] = None
    if is_enable in {"yes", "no"}:
        enabled = is_enable == "yes"

    return RecordBase(
        name=str(resource.get("name", "")),
        value=value,
        enabled=enabled,
        dc=None,
        weight=None,
    )


def _build_static_domain_results(
    resources: List[Dict[str, Any]],
) -> List[DomainResultBase]:
    grouped_resources: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    for resource in resources:
        name = str(resource.get("name", ""))
        record_type = str(resource.get("type", ""))
        grouped_resources.setdefault((name, record_type), []).append(resource)

    results: List[DomainResultBase] = []
    for (name, record_type), items in grouped_resources.items():
        first_item = items[0]
        is_enable = str(first_item.get("is_enable", "")).lower()
        enabled: Optional[bool] = None
        if is_enable in {"yes", "no"}:
            enabled = is_enable == "yes"

        results.append(
            DomainResultBase(
                name=name,
                type=record_type,
                algorithm=None,
                enable=enabled,
                ttl=_safe_int(first_item.get("ttl")),
                records=[_build_static_record(item) for item in items],
                pools=[],
            )
        )

    return results


def _sort_domain_results(
    results: List[DomainResultBase],
    orders: Optional[OrderBase],
) -> List[DomainResultBase]:
    if orders is None:
        return results

    reverse = orders.order_type == "DESC"
    order_key = orders.order_key

    def _result_key(item: DomainResultBase) -> Any:
        value = getattr(item, order_key, None)
        if isinstance(value, bool):
            return int(value)
        if value is None:
            return ""
        return str(value)

    return sorted(results, key=_result_key, reverse=reverse)


def query_domain(data: Dict[str, Any]) -> QueryDomainResponseBase:
    try:
        request_data = QueryDomainRequest.model_validate(data)
        _log_step(
            "query_domain",
            "输入参数校验通过",
            conditions=[
                item.model_dump(by_alias=True) for item in request_data.conditions
            ],
            orders=request_data.orders.model_dump() if request_data.orders else None,
        )
    except ValidationError as exc:
        _log_exception("query_domain", "输入参数校验失败")
        return QueryDomainResponseBase(
            success=False,
            message=[f"输入参数校验失败: {exc}"],
        )

    query_scope = _extract_query_scope(request_data.conditions)
    if query_scope not in {"dynamic", "static", "all"}:
        return QueryDomainResponseBase(
            success=False,
            message=[f"不支持的查询类型: {query_scope}"],
        )

    result: List[DomainResultBase] = []
    message: List[str] = []

    if query_scope in {"dynamic", "all"}:
        dynamic_result, dynamic_messages, dynamic_error = _query_dynamic_domain_results(
            request_data
        )
        if dynamic_error is not None:
            return QueryDomainResponseBase(success=False, message=[dynamic_error])
        result.extend(dynamic_result)
        message.extend(dynamic_messages)

    if query_scope in {"static", "all"}:
        static_result, static_messages, static_error = _query_static_domain_results(
            request_data
        )
        if static_error is not None:
            return QueryDomainResponseBase(success=False, message=[static_error])
        result.extend(static_result)
        message.extend(static_messages)

    result = _sort_domain_results(result, request_data.orders)
    message.insert(0, f"查询成功，共匹配到 {len(result)} 条域名记录")

    return QueryDomainResponseBase(
        success=True,
        result=result,
        message=message,
    )


def main() -> int:
    input_path = (
        sys.argv[1] if len(sys.argv) > 1 else _default_input_path("query_domain.json")
    )
    _log_step("main", "脚本启动", input_path=input_path, log_file=LOG_FILE)

    try:
        input_data = _load_input_data(input_path)
    except (OSError, json.JSONDecodeError) as exc:
        _log_exception("main", f"读取输入文件失败: {input_path}")
        _print_cli_error(f"读取输入文件失败: {exc}")
        return 1

    response = query_domain(input_data)
    _log_step("main", "脚本执行完成", success=response.success)
    _print_cli_result(response)
    return 0 if response.success else 1


if __name__ == "__main__":
    sys.exit(main())
