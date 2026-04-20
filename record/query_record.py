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


class DeviceInfo(BaseModel):
    management_ip: str = Field(..., description="管理节点 IP")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


class RecordItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = Field(default=None, description="服务成员名称")
    value: Optional[str] = Field(default=None, description="服务成员 IP")
    port: Optional[int] = Field(default=None, description="服务成员端口")
    enable: Optional[bool] = Field(
        default=None, alias="enabled", description="是否启用"
    )
    dc: Optional[str] = Field(default=None, description="数据中心名称")

    @model_validator(mode="before")
    @classmethod
    def fill_enable_alias(cls, data: Any) -> Any:
        if isinstance(data, dict) and "enabled" not in data and "enable" in data:
            data = dict(data)
            data["enabled"] = data["enable"]
        return data

    @model_validator(mode="after")
    def normalize_values(self) -> "RecordItem":
        if self.name is not None:
            self.name = self.name.strip() or None
        if self.value is not None:
            self.value = self.value.strip() or None
        if self.dc is not None:
            self.dc = self.dc.strip() or None
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


class AdditionsBase(BaseModel):
    limit: int = Field(default=100, ge=1, description="查询结果限制数量")
    orders: Optional[OrderBase] = Field(default=None, description="排序参数")
    match_type: str = Field(default="fuzzy", description="匹配类型，fuzzy 或 exact")

    @model_validator(mode="after")
    def normalize_match_type(self) -> "AdditionsBase":
        self.match_type = self.match_type.lower()
        if self.match_type not in {"fuzzy", "exact"}:
            raise ValueError("match_type 仅支持 fuzzy 或 exact")
        return self


class QueryRecordRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["query_records"] = Field(..., description="操作类型")
    record: RecordItem = Field(..., description="查询条件")
    additions: AdditionsBase = Field(..., description="附加查询参数")

    @model_validator(mode="after")
    def validate_record_not_empty(self) -> "QueryRecordRequest":
        if (
            self.record.name is None
            and self.record.value is None
            and self.record.port is None
            and self.record.enable is None
            and self.record.dc is None
        ):
            raise ValueError("record 至少需要提供一个查询条件")
        return self


#############################################################
### 标准输出规范 ###


class RecordInfo(BaseModel):
    name: str = Field(..., description="记录名称")
    value: str = Field(..., description="记录值")
    port: int = Field(..., description="端口")
    enable: bool = Field(..., description="是否启用")
    dc: str = Field(..., description="数据中心")


class QueryRecordResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    records: List[RecordInfo] = Field(
        default_factory=list, description="查询到的记录列表"
    )
    message: List[str] = Field(default_factory=list, description="操作结果消息")


#############################################################
### API: 查询数据中心 ###


def get_dc(
    host: str,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    url = f"https://{host}:20120/dc"
    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{host}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }

    _log_step("get_dc", "准备发送查询数据中心请求", url=url)

    response = requests.get(
        url,
        headers=headers,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("get_dc", response)
    return response


#############################################################
### API: 查询数据中心成员 ###


class GmemberParamsBase(BaseModel):
    host: str = Field(..., description="设备管理IP")
    dc: str = Field(..., description="数据中心名称")
    search_attrs: List[List[str]] = Field(default_factory=list, description="搜索条件")
    version: str = Field(default="2", description="API版本")


def _build_gmember_query(search_attrs: List[List[str]], version: str = "2") -> str:
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

    query_parts.append(f"version={quote(str(version), safe='')}")
    return "&".join(query_parts)


def get_gmember(
    req: GmemberParamsBase,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)
    dc_value = payload.pop("dc", None)

    url = f"https://{host_value}:20120/dc/{dc_value}/gmember"
    query_string = _build_gmember_query(req.search_attrs, req.version)
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
        "get_gmember",
        "准备发送查询数据中心服务成员请求",
        url=request_url,
        dc=dc_value,
        search_attrs=req.search_attrs,
    )

    response = requests.get(
        request_url,
        headers=headers,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("get_gmember", response)
    return response


#############################################################
### 查询数据中心成员核心逻辑 ###


def _parse_dc_response(response: requests.Response) -> List[Dict[str, Any]]:
    response_data = response.json()
    if not isinstance(response_data, dict):
        raise ValueError("数据中心查询接口返回格式异常")

    resources = response_data.get("resources", [])
    if not isinstance(resources, list):
        raise ValueError("数据中心查询接口缺少 resources 列表")

    return [resource for resource in resources if isinstance(resource, dict)]


def _parse_gmember_response(
    response: requests.Response, dc_name: str
) -> List[Dict[str, Any]]:
    response_data = response.json()

    if isinstance(response_data, dict):
        resources = response_data.get("resources")
        if isinstance(resources, list):
            result: List[Dict[str, Any]] = []
            for member in resources:
                if not isinstance(member, dict):
                    continue
                normalized_member = dict(member)
                normalized_member.setdefault("dc_name", dc_name)
                result.append(normalized_member)
            return result

        members = response_data.get(dc_name)
        if isinstance(members, list):
            result = []
            for member in members:
                if not isinstance(member, dict):
                    continue
                normalized_member = dict(member)
                normalized_member.setdefault("dc_name", dc_name)
                result.append(normalized_member)
            return result

    raise ValueError("数据中心服务成员查询接口返回格式异常")


def _build_dc_names(
    dc_resources: List[Dict[str, Any]], record: RecordItem, match_type: str
) -> List[str]:
    dc_names: List[str] = []

    for resource in dc_resources:
        dc_name = str(resource.get("name", "")).strip()
        if dc_name == "":
            continue

        if record.dc is not None:
            if match_type == "exact" and dc_name != record.dc:
                continue
            if match_type == "fuzzy" and record.dc not in dc_name:
                continue

        dc_names.append(dc_name)

    return dc_names


def _build_gmember_search_attrs(record: RecordItem, match_type: str) -> List[List[str]]:
    operator = "eq" if match_type == "exact" else "in"
    search_attrs: List[List[str]] = []

    if record.name is not None:
        search_attrs.append(["gmember_name", operator, record.name, "and"])

    if record.value is not None:
        search_attrs.append(["ip", operator, record.value, "and"])

    if record.port is not None:
        search_attrs.append(["port", operator, str(record.port), "and"])

    if record.enable is not None:
        search_attrs.append(["enable", "eq", "yes" if record.enable else "no", "and"])

    return search_attrs


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_record_info(member: Dict[str, Any], dc_name: str) -> Optional[RecordInfo]:
    member_name = str(member.get("gmember_name", "")).strip()
    if member_name == "":
        return None

    member_ip = str(member.get("ip", "")).strip()
    member_enable = str(member.get("enable", "")).lower() == "yes"
    member_dc = str(member.get("dc_name", "")).strip() or dc_name

    return RecordInfo(
        name=member_name,
        value=member_ip,
        port=_safe_int(member.get("port"), default=0),
        enable=member_enable,
        dc=member_dc,
    )


def _matches_record(item: RecordInfo, record: RecordItem, match_type: str) -> bool:
    def _match_string(actual: str, expected: str) -> bool:
        if match_type == "exact":
            return actual == expected
        return expected in actual

    if record.name is not None and not _match_string(item.name, record.name):
        return False

    if record.value is not None and not _match_string(item.value, record.value):
        return False

    if record.dc is not None and not _match_string(item.dc, record.dc):
        return False

    if record.port is not None:
        if match_type == "exact" and item.port != record.port:
            return False
        if match_type == "fuzzy" and str(record.port) not in str(item.port):
            return False

    if record.enable is not None and item.enable != record.enable:
        return False

    return True


def _normalize_order_key(order_key: str) -> str:
    order_mapping = {
        "record_name": "name",
        "record_value": "value",
        "record_port": "port",
        "enabled": "enable",
    }
    return order_mapping.get(order_key, order_key)


def _sort_records(
    records: List[RecordInfo], orders: Optional[OrderBase]
) -> List[RecordInfo]:
    if orders is None:
        return records

    order_key = _normalize_order_key(orders.order_key)
    reverse = orders.order_type == "DESC"

    def _sort_key(item: RecordInfo) -> Any:
        value = getattr(item, order_key, "")
        if isinstance(value, bool):
            return int(value)
        return value

    return sorted(records, key=_sort_key, reverse=reverse)


def query_record(data: Dict[str, Any]) -> QueryRecordResponse:
    try:
        request_data = QueryRecordRequest.model_validate(data)
        _log_step(
            "query_record",
            "输入参数校验通过",
            record=request_data.record.model_dump(by_alias=True, exclude_none=True),
            additions=request_data.additions.model_dump(exclude_none=True),
        )
    except ValidationError as exc:
        _log_exception("query_record", "输入参数校验失败")
        return QueryRecordResponse(
            success=False,
            message=[f"输入参数校验失败: {exc}"],
        )

    auth = (
        request_data.device_info.username,
        request_data.device_info.password,
    )

    try:
        dc_response = get_dc(request_data.device_info.management_ip, auth=auth)
    except requests.RequestException as exc:
        _log_exception("query_record", "查询数据中心请求失败")
        return QueryRecordResponse(
            success=False,
            message=[f"查询数据中心请求失败: {exc}"],
        )

    if not dc_response.ok:
        return QueryRecordResponse(
            success=False,
            message=[
                f"查询数据中心失败，HTTP状态码: {dc_response.status_code}",
                dc_response.text,
            ],
        )

    try:
        dc_resources = _parse_dc_response(dc_response)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        _log_exception("query_record", "解析数据中心查询结果失败")
        return QueryRecordResponse(
            success=False,
            message=[f"解析数据中心查询结果失败: {exc}"],
        )

    dc_names = _build_dc_names(
        dc_resources,
        request_data.record,
        request_data.additions.match_type,
    )
    if not dc_names:
        return QueryRecordResponse(
            success=True,
            records=[],
            message=["未匹配到可查询的数据中心"],
        )

    search_attrs = _build_gmember_search_attrs(
        request_data.record,
        request_data.additions.match_type,
    )

    records: List[RecordInfo] = []
    messages: List[str] = []
    had_error = False

    for dc_name in dc_names:
        try:
            gmember_response = get_gmember(
                GmemberParamsBase(
                    host=request_data.device_info.management_ip,
                    dc=dc_name,
                    search_attrs=search_attrs,
                ),
                auth=auth,
            )
        except requests.RequestException as exc:
            _log_exception("query_record", "查询数据中心服务成员请求失败")
            messages.append(f"数据中心 {dc_name}: 查询服务成员请求失败: {exc}")
            had_error = True
            continue

        if not gmember_response.ok:
            messages.append(
                f"数据中心 {dc_name}: 查询服务成员失败, status={gmember_response.status_code}, body={gmember_response.text[:200]}"
            )
            had_error = True
            continue

        try:
            members = _parse_gmember_response(gmember_response, dc_name)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            _log_exception("query_record", "解析数据中心服务成员结果失败")
            messages.append(f"数据中心 {dc_name}: 解析服务成员结果失败: {exc}")
            had_error = True
            continue

        for member in members:
            record_info = _build_record_info(member, dc_name)
            if record_info is None:
                continue
            if _matches_record(
                record_info,
                request_data.record,
                request_data.additions.match_type,
            ):
                records.append(record_info)

    records = _sort_records(records, request_data.additions.orders)
    records = records[: request_data.additions.limit]

    summary = f"查询完成，共匹配到 {len(records)} 条服务成员记录"
    if messages:
        messages.insert(0, summary)
    else:
        messages = [summary]

    return QueryRecordResponse(
        success=not had_error,
        records=records,
        message=messages,
    )


def main() -> int:
    input_path = (
        sys.argv[1] if len(sys.argv) > 1 else _default_input_path("query_record.json")
    )
    _log_step("main", "脚本启动", input_path=input_path, log_file=LOG_FILE)

    try:
        input_data = _load_input_data(input_path)
    except (OSError, json.JSONDecodeError) as exc:
        _log_exception("main", f"读取输入文件失败: {input_path}")
        _print_cli_error(f"读取输入文件失败: {exc}")
        return 1

    response = query_record(input_data)
    _log_step("main", "脚本执行完成", success=response.success)
    _print_cli_result(response)
    return 0 if response.success else 1


if __name__ == "__main__":
    sys.exit(main())
