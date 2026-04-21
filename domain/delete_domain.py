import json
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
import sys
from typing import Any, Dict, List, Literal, Optional, Tuple, Union
from urllib.parse import quote, quote_plus

import requests
import urllib3
from pydantic import BaseModel, ConfigDict, Field, ValidationError

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
### 公共方法 ###


def _build_dns_search_query(search_attrs: List[List[str]]) -> str:
    query_parts: List[str] = []

    for index, attrs in enumerate(search_attrs):
        key = f"search_key[{index}][]"
        for attr in attrs:
            query_parts.append(f"{key}={quote(str(attr), safe='[]')}")

    return "&".join(query_parts)


def _encode_form_value(value: Any) -> str:
    return quote_plus(str(value), safe=".:/$-_")


#############################################################
### 标准输入规范 ###


class DeviceInfo(BaseModel):
    management_ip: str = Field(..., description="管理节点 IP")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


class DataBase(BaseModel):
    name: str = Field(..., description="域名")
    type: str = Field(..., description="静态动态类别，如 static、dynamic 或 all")
    deleted: bool = Field(default=False, description="是否删除成功")


class DeleteDomainRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["delete_domain"] = Field(..., description="操作类型")
    data: Union[DataBase, List[DataBase]] = Field(..., description="数据")


#############################################################
### 标准输出规范 ###


class DeleteDomainResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: List[DataBase] = Field(default_factory=list, description="操作结果数据")
    message: List[str] = Field(default_factory=list, description="操作结果消息")


############################################################
### API: 动态域名查询 ###


class GMapQueryParams(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图必须是 ADD")
    zone: str = Field(..., description="域名区")
    search_attrs: List[List[str]] = Field(..., description="搜索属性嵌套列表")
    version: int = Field(default=2, description="接口版本")


def get_gmap_record(
    req: GMapQueryParams, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)
    view_value = payload.pop("view", None)
    zone_value = payload.pop("zone", None)
    search_attrs = payload.get("search_attrs", [])

    url = f"https://{host_value}:20120/views/{view_value}/dzone/{zone_value}/gmap"
    query_string = _build_dns_search_query(search_attrs)
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
    )

    response = requests.get(request_url, headers=headers, verify=verify_ssl, auth=auth)
    _log_http_response("get_gmap_record", response)
    return response


#############################################################
### API: 动态域名删除 ###


class GMapDeleteRequest(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图必须是 ADD")
    zone: str = Field(..., description="域名区")
    ids: List[str] = Field(..., description="记录 ID 列表")


def delete_gmap_record(
    req: GMapDeleteRequest,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)
    view_value = payload.pop("view", None)
    zone_value = payload.pop("zone", None)

    url = f"https://{host_value}:20120/views/{view_value}/dzone/{zone_value}/gmap"

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
        "delete_gmap_record",
        "准备发送动态域名删除请求",
        url=url,
        zone=zone_value,
        record_ids=payload.get("ids"),
    )

    response = requests.delete(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("delete_gmap_record", response)
    return response


############################################################
### API: 静态域名查询 ###


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
    query_string = _build_dns_search_query(search_attrs)
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

    response = requests.get(request_url, headers=headers, verify=verify_ssl, auth=auth)
    _log_http_response("dns_search_resources", response)
    return response


############################################################
### API: 静态域名删除 ###


class RrsDeleteRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="主机 IP")
    ids: List[str] = Field(..., description="记录 ID 列表")
    desc: Dict[str, str] = Field(
        ...,
        alias="_desc",
        serialization_alias="_desc",
        description="记录 ID 与描述的映射关系",
    )
    link_ptr: str = Field(default="no", description="是否关联 PTR")
    link_cname: str = Field(default="no", description="是否关联 CNAME")
    link_srv: str = Field(default="no", description="是否关联 SRV")
    link_mx: str = Field(default="no", description="是否关联 MX")


def _build_rrs_delete_body(req: RrsDeleteRequest) -> Tuple[str, str]:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = str(payload.pop("host", ""))
    desc_map = payload.get("_desc", {})
    record_ids = payload.get("ids", [])

    body_parts: List[str] = []
    for record_id in record_ids:
        record_id_text = str(record_id)
        desc_text = str(desc_map.get(record_id_text, ""))
        body_parts.append(f"_desc[{record_id_text}]={_encode_form_value(desc_text)}")

    body_parts.extend(
        [
            f"link_ptr={_encode_form_value(payload.get('link_ptr', 'no'))}",
            f"link_cname={_encode_form_value(payload.get('link_cname', 'no'))}",
            f"link_srv={_encode_form_value(payload.get('link_srv', 'no'))}",
            f"link_mx={_encode_form_value(payload.get('link_mx', 'no'))}",
        ]
    )

    for record_id in record_ids:
        body_parts.append(f"ids[]={_encode_form_value(record_id)}")

    return host_value, "&".join(body_parts)


def delete_rrs_record(
    req: RrsDeleteRequest,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    host_value, body_string = _build_rrs_delete_body(req)
    url = f"https://{host_value}:20120/dns-search-resources"

    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": f"https://{host_value}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }

    _log_step(
        "delete_rrs_record",
        "准备发送静态域名删除请求",
        url=url,
        body_preview=body_string[:300],
    )

    response = requests.delete(
        url, headers=headers, data=body_string, verify=verify_ssl, auth=auth
    )
    _log_http_response("delete_rrs_record", response)
    return response


############################################################
### 删除域名核心逻辑 ###


def _ensure_fqdn(name: str) -> str:
    return name if name.endswith(".") else f"{name}."


def _build_dynamic_zone_name(name: str) -> str:
    fqdn = _ensure_fqdn(name).rstrip(".")
    labels = fqdn.split(".")
    if len(labels) < 2:
        raise ValueError(f"非法域名: {name}")
    return f"{labels[-2]}.{labels[-1]}."


def _parse_response_json(
    response: requests.Response, module: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    content_type = response.headers.get("Content-Type", "")
    if "json" not in content_type.lower():
        _log_step(module, "接口返回的不是 JSON", content_type=content_type)
        return None, f"接口返回的不是 JSON: {content_type or 'unknown'}"

    try:
        payload = response.json()
    except requests.exceptions.JSONDecodeError:
        _log_exception(module, "接口返回内容无法解析为 JSON")
        return None, "接口返回内容无法解析为 JSON"

    if not isinstance(payload, dict):
        _log_step(module, "接口返回 JSON 结构异常", payload=payload)
        return None, "接口返回 JSON 结构异常"

    return payload, None


def _extract_resource_ids(resources: List[Dict[str, Any]]) -> List[str]:
    return [str(item["id"]) for item in resources if item.get("id")]


def _build_rrs_desc_map(resources: List[Dict[str, Any]]) -> Dict[str, str]:
    desc_map: Dict[str, str] = {}

    for resource in resources:
        resource_id = str(resource.get("id", "")).strip()
        if not resource_id:
            continue

        desc_value = resource.get("_desc")
        if desc_value is None:
            rdata = (
                resource.get("rdata") or resource.get("value") or resource.get("data")
            )
            if isinstance(rdata, list):
                rdata_text = " ".join(str(item) for item in rdata)
            else:
                rdata_text = str(rdata or "")

            desc_value = " ".join(
                part
                for part in [
                    str(resource.get("name", "")).strip(),
                    str(resource.get("type", "")).strip(),
                    rdata_text.strip(),
                ]
                if part
            )

        desc_map[resource_id] = str(desc_value)

    return desc_map


def _response_message(prefix: str, response: requests.Response) -> str:
    response_text = response.text.strip() or "无返回内容"
    return f"{prefix}: {response.status_code} - {response_text}"


def _build_delete_domain_response(
    success: bool,
    result: List[DataBase],
    message: Optional[List[str]] = None,
) -> DeleteDomainResponse:
    return DeleteDomainResponse(
        success=success,
        result=result,
        message=message or [],
    )


def _build_single_delete_domain_response(
    success: bool,
    result: DataBase,
    message: Optional[List[str]] = None,
) -> DeleteDomainResponse:
    return _build_delete_domain_response(
        success=success,
        result=[result],
        message=message,
    )


def _normalize_delete_domain_items(
    items: Union[DataBase, List[DataBase]],
) -> List[DataBase]:
    if isinstance(items, list):
        return items
    return [items]


def _prefix_messages(domain_name: str, messages: List[str]) -> List[str]:
    return [f"{domain_name}: {message}" for message in messages]


def _delete_dynamic_domain_records(
    device_info: DeviceInfo,
    domain_name: str,
) -> Tuple[str, List[str]]:
    auth = (device_info.username, device_info.password)
    record_fqdn = _ensure_fqdn(domain_name)
    zone_name = _build_dynamic_zone_name(domain_name)

    query_response = get_gmap_record(
        GMapQueryParams(
            host=device_info.management_ip,
            zone=zone_name,
            search_attrs=[["name", "eq", record_fqdn, "and"]],
        ),
        auth=auth,
    )
    if not query_response.ok:
        return "error", [_response_message("查询动态域名失败", query_response)]

    payload, payload_error = _parse_response_json(query_response, "delete-domain")
    if payload_error:
        return "error", [payload_error]

    resources = (payload or {}).get("resources", [])
    if not isinstance(resources, list) or not resources:
        return "not_found", [f"未找到可删除的动态域名记录: {record_fqdn}"]

    record_ids = _extract_resource_ids(resources)
    if not record_ids:
        return "error", [f"动态域名记录缺少可用 id: {record_fqdn}"]

    delete_response = delete_gmap_record(
        GMapDeleteRequest(
            host=device_info.management_ip,
            zone=zone_name,
            ids=record_ids,
        ),
        auth=auth,
    )

    return (
        "success" if delete_response.ok else "error",
        [
            f"动态域名匹配到 {len(record_ids)} 条记录",
            _response_message("删除动态域名结果", delete_response),
        ],
    )


def _delete_static_domain_records(
    device_info: DeviceInfo,
    domain_name: str,
) -> Tuple[str, List[str]]:
    auth = (device_info.username, device_info.password)
    record_fqdn = _ensure_fqdn(domain_name)

    query_response = dns_search_resources(
        RrsQueryParams(
            host=device_info.management_ip,
            search_attrs=[["name", "eq", record_fqdn, "and"]],
        ),
        auth=auth,
    )
    if not query_response.ok:
        return "error", [_response_message("查询静态域名失败", query_response)]

    payload, payload_error = _parse_response_json(query_response, "delete-domain")
    if payload_error:
        return "error", [payload_error]

    resources = (payload or {}).get("resources", [])
    if not isinstance(resources, list) or not resources:
        return "not_found", [f"未找到可删除的静态域名记录: {record_fqdn}"]

    record_ids = _extract_resource_ids(resources)
    if not record_ids:
        return "error", [f"静态域名记录缺少可用 id: {record_fqdn}"]

    delete_response = delete_rrs_record(
        RrsDeleteRequest(
            host=device_info.management_ip,
            ids=record_ids,
            _desc=_build_rrs_desc_map(resources),
        ),
        auth=auth,
    )

    return (
        "success" if delete_response.ok else "error",
        [
            f"静态域名匹配到 {len(record_ids)} 条记录",
            _response_message("删除静态域名结果", delete_response),
        ],
    )


def _process_delete_domain_item(
    device_info: DeviceInfo,
    domain_data: DataBase,
) -> DeleteDomainResponse:
    domain_name = domain_data.name.strip()
    domain_type = domain_data.type.strip().lower()

    _log_step(
        "delete-domain",
        "开始处理单个域名",
        domain_name=domain_name,
        domain_type=domain_type,
    )

    try:
        if domain_type not in {"dynamic", "static", "all"}:
            return _build_single_delete_domain_response(
                success=False,
                result=domain_data.model_copy(update={"deleted": False}),
                message=[f"不支持的域名类型: {domain_data.type}"],
            )

        handlers = {
            "dynamic": _delete_dynamic_domain_records,
            "static": _delete_static_domain_records,
        }
        target_types = [domain_type] if domain_type != "all" else ["dynamic", "static"]

        statuses: List[str] = []
        messages: List[str] = []
        for target_type in target_types:
            status, target_messages = handlers[target_type](device_info, domain_name)
            statuses.append(status)
            messages.extend(target_messages)

        has_success = any(status == "success" for status in statuses)
        has_error = any(status == "error" for status in statuses)
        has_not_found = any(status == "not_found" for status in statuses)

        if domain_type == "all":
            if not has_success and has_not_found and not has_error:
                messages.append("动态和静态域名均未匹配到可删除记录")
            if has_success and has_error:
                messages.append("删除存在部分失败，请检查上述接口返回")
            success = has_success and not has_error
        else:
            success = statuses[0] == "success"

        return _build_single_delete_domain_response(
            success=success,
            result=domain_data.model_copy(update={"deleted": success}),
            message=messages,
        )
    except (ValidationError, ValueError) as error:
        _log_exception(
            "delete-domain", f"处理 delete_domain 时发生校验或值错误: {error}"
        )
        return _build_single_delete_domain_response(
            success=False,
            result=domain_data.model_copy(update={"deleted": False}),
            message=[str(error)],
        )
    except requests.RequestException as error:
        _log_exception("delete-domain", f"处理 delete_domain 时发生请求异常: {error}")
        return _build_single_delete_domain_response(
            success=False,
            result=domain_data.model_copy(update={"deleted": False}),
            message=[str(error)],
        )


def delete_domain(data: Dict[str, Any]) -> DeleteDomainResponse:
    """
    删除域名核心逻辑：
    1. 验证输入数据。
    2. 根据域名类型查询待删除记录。
    3. 动态域名按记录 ID 发送 JSON 删除请求。
    4. 静态域名将 _desc 和 ids[] 拼接为字符串请求体后发送删除请求。
    5. 聚合批量处理结果并返回标准输出。
    """

    _log_step("delete-domain", "开始处理 delete_domain 请求", input_data=data)

    fallback_results: List[DataBase] = []
    raw_items = data.get("data", [])
    if isinstance(raw_items, dict):
        raw_items = [raw_items]
    if isinstance(raw_items, list):
        for item in raw_items:
            if isinstance(item, dict):
                fallback_results.append(
                    DataBase(
                        name=str(item.get("name", "")),
                        type=str(item.get("type", "")),
                        deleted=False,
                    )
                )

    try:
        request = DeleteDomainRequest.model_validate(data)
    except ValidationError as error:
        _log_step("delete-domain", "输入校验失败", errors=error.errors())
        return _build_delete_domain_response(
            success=False,
            result=fallback_results,
            message=[error.json(indent=2)],
        )

    items = _normalize_delete_domain_items(request.data)

    _log_step(
        "delete-domain",
        "输入校验成功",
        total=len(items),
        domain_names=[item.name for item in items],
    )

    results: List[DataBase] = []
    messages: List[str] = []
    success = True

    for item in items:
        item_response = _process_delete_domain_item(request.device_info, item)
        results.extend(item_response.result)
        messages.extend(_prefix_messages(item.name, item_response.message))
        success = success and item_response.success

    return _build_delete_domain_response(
        success=success,
        result=results,
        message=messages,
    )


############################################################


def main() -> int:
    input_path = (
        sys.argv[1] if len(sys.argv) > 1 else _default_input_path("delete_domain.json")
    )
    _log_step("main", "脚本启动", input_path=input_path, log_file=LOG_FILE)

    try:
        input_data = _load_input_data(input_path)
    except (OSError, json.JSONDecodeError) as exc:
        _log_exception("main", f"读取输入文件失败: {input_path}")
        _print_cli_error(f"读取输入文件失败: {exc}")
        return 1

    result = delete_domain(input_data)
    _log_step("main", "脚本执行完成", success=result.success)
    _print_cli_result(result)
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
