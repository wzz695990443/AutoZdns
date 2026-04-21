import json
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
import requests
import urllib3
import sys
from typing import List, Dict, Any, Optional, Literal, Tuple, Union
from urllib.parse import quote

from pydantic import BaseModel, Field, ValidationError, model_validator, ConfigDict

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


class DataBase(BaseModel):
    name: str = Field(..., description="域名")
    type: Literal["static", "dynamic"] = Field(..., description="域名类型")
    algorithm: Optional[str] = Field(default=None, description="动态域名调度算法")
    ttl: Optional[int] = Field(default=None, description="TTL")
    qps: Optional[Union[int, str]] = Field(default=None, description="兼容保留字段")

    @model_validator(mode="after")
    def normalize_values(self) -> "DataBase":
        self.name = self.name.strip()
        if self.algorithm is not None:
            self.algorithm = self.algorithm.strip() or None
        if self.ttl is not None and self.ttl <= 0:
            raise ValueError("ttl 必须大于 0")
        if self.type == "static" and self.algorithm is not None:
            self.algorithm = None
        if self.type == "dynamic" and self.algorithm is None and self.ttl is None:
            raise ValueError("动态域名至少需要修改 algorithm 或 ttl 其中一个属性")
        if self.type == "static" and self.ttl is None:
            raise ValueError("静态域名修改时 ttl 不能为空")
        return self


class ModifyDomainRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["modify_domain"] = Field(..., description="操作类型")
    data: Union[DataBase, List[DataBase]] = Field(..., description="修改数据")


#############################################################
### 标准输出规范 ###


class ModifyDomainResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: List[DataBase] = Field(default_factory=list, description="操作结果数据")
    message: List[str] = Field(default_factory=list, description="操作结果消息")


#############################################################
### 公共 API ###


def _build_search_attrs_query(search_attrs: List[List[str]], version: str = "2") -> str:
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


def _build_dns_search_query(search_attrs: List[List[str]]) -> str:
    query_parts: List[str] = []

    for index, attrs in enumerate(search_attrs):
        key = f"search_key[{index}][]"
        for attr in attrs:
            query_parts.append(f"{key}={quote(str(attr), safe='[]')}")

    return "&".join(query_parts)


def _ensure_fqdn(name: str) -> str:
    return name if name.endswith(".") else f"{name}."


def _build_dynamic_zone_name(name: str) -> str:
    fqdn = _ensure_fqdn(name).rstrip(".")
    labels = fqdn.split(".")
    if len(labels) < 2:
        raise ValueError(f"非法域名: {name}")
    return f"{labels[-2]}.{labels[-1]}."


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


def _response_message(prefix: str, response: requests.Response) -> str:
    body = response.text.strip() or "无返回内容"
    return f"{prefix}: {response.status_code} - {body}"


#############################################################
### API: 动态域名查询/修改 ###


class GMapQueryParams(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图")
    zone: str = Field(..., description="域名区")
    search_attrs: List[List[str]] = Field(..., description="查询条件")
    version: str = Field(default="2", description="接口版本")


class PutGMapRequest(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图")
    zone: str = Field(..., description="域名区")
    ids: List[str] = Field(..., description="记录 ID 列表")
    algorithm: str = Field(..., description="动态域名算法")
    enable: str = Field(..., description="启用状态")


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
    query_string = _build_search_attrs_query(req.search_attrs, req.version)
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
        "get_gmap_record", "准备发送动态域名查询请求", url=request_url, zone=zone_value
    )
    response = requests.get(request_url, headers=headers, verify=verify_ssl, auth=auth)
    _log_http_response("get_gmap_record", response)
    return response


def put_gmap_record(
    req: PutGMapRequest,
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
        "put_gmap_record",
        "准备发送动态域名更新请求",
        url=url,
        zone=zone_value,
        ids=payload.get("ids", []),
        algorithm=payload.get("algorithm"),
    )
    response = requests.put(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("put_gmap_record", response)
    return response


#############################################################
### API: 静态域名查询/修改 ###


class RrsQueryParams(BaseModel):
    host: str = Field(..., description="主机 IP")
    search_attrs: List[List[str]] = Field(..., description="查询条件")


class PutRrsRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="主机 IP")
    ttl: int = Field(..., description="TTL")
    ids: List[str] = Field(..., description="记录 ID 列表")
    desc: Dict[str, str] = Field(
        ...,
        alias="_desc",
        serialization_alias="_desc",
        description="记录描述映射",
    )


def dns_search_resources(
    req: RrsQueryParams,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)

    url = f"https://{host_value}:20120/dns-search-resources"
    query_string = _build_dns_search_query(req.search_attrs)
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

    _log_step("dns_search_resources", "准备发送静态域名查询请求", url=request_url)
    response = requests.get(request_url, headers=headers, verify=verify_ssl, auth=auth)
    _log_http_response("dns_search_resources", response)
    return response


def put_rrs_record(
    req: PutRrsRequest,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)

    url = f"https://{host_value}:20120/dns-search-resources"

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
        "put_rrs_record",
        "准备发送静态域名更新请求",
        url=url,
        ids=payload.get("ids", []),
        ttl=payload.get("ttl"),
    )
    response = requests.put(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("put_rrs_record", response)
    return response


#############################################################
### API: 地址池查询/修改 ###


class GpoolQueryParams(BaseModel):
    host: str = Field(..., description="设备管理IP")
    pool_names: List[str] = Field(..., description="地址池名称列表")
    version: str = Field(default="2", description="API版本")


class PutGpoolRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="设备管理IP")
    ttl: int = Field(default=30, description="地址池TTL")
    max_addr_ret: int = Field(default=1, description="地址池最大返回记录数")
    hm_gm_flag: str = Field(default="yes", description="服务成员状态检测")
    hms: List[str] = Field(default_factory=list, description="健康检测列表")
    pass_: str = Field(default="1", alias="pass", description="占位字段")
    hm_gool_flag: str = Field(default="no", description="活跃地址数检测")
    warning: str = Field(default="yes", description="异常处理")
    first_algorithm: str = Field(..., description="一级调度算法")
    second_algorithm: str = Field(..., description="二级调度算法")
    auto_disabled: str = Field(default="no", description="是否自动禁用地址池")
    enable: str = Field(default="no", description="是否启用地址池")
    key_1: str = Field(default="", alias="key_1", description="备注")
    ids: List[str] = Field(..., description="地址池ID列表")


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


def get_gpool(
    req: GpoolQueryParams,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)

    url = f"https://{host_value}:20120/gpool"
    query_string = _build_gpool_query(req.pool_names, req.version)
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
        "准备发送查询地址池请求",
        url=request_url,
        pool_names=req.pool_names,
    )
    response = requests.get(request_url, headers=headers, verify=verify_ssl, auth=auth)
    _log_http_response("get_gpool", response)
    return response


def put_gpool(
    req: PutGpoolRequest,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)

    url = f"https://{host_value}:20120/gpool"

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
        "put_gpool",
        "准备发送更新地址池请求",
        url=url,
        ids=payload.get("ids", []),
        ttl=payload.get("ttl"),
    )
    response = requests.put(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("put_gpool", response)
    return response


#############################################################
### 修改逻辑 ###


def _extract_resource_ids(resources: List[Dict[str, Any]]) -> List[str]:
    return [
        str(item.get("id", "")).strip()
        for item in resources
        if str(item.get("id", "")).strip() != ""
    ]


def _build_rrs_desc_map(resources: List[Dict[str, Any]]) -> Dict[str, str]:
    desc_map: Dict[str, str] = {}

    for resource in resources:
        resource_id = str(resource.get("id", "")).strip()
        if resource_id == "":
            continue

        desc_value = resource.get("_desc")
        if desc_value is None:
            rdata = resource.get("rdata")
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


def _build_put_gpool_request(
    resource: Dict[str, Any], ttl: int, host: str
) -> PutGpoolRequest:
    payload = {
        "host": host,
        "ttl": ttl,
        "max_addr_ret": int(resource.get("max_addr_ret", 1)),
        "hm_gm_flag": str(resource.get("hm_gm_flag", "yes")),
        "hms": (
            resource.get("hms", []) if isinstance(resource.get("hms", []), list) else []
        ),
        "pass": "1",
        "hm_gool_flag": str(resource.get("hm_gool_flag", "no")),
        "warning": str(resource.get("warning", "yes")),
        "first_algorithm": str(resource.get("first_algorithm", "wrr")),
        "second_algorithm": str(resource.get("second_algorithm", "none")),
        "auto_disabled": str(resource.get("auto_disabled", "no")),
        "enable": str(resource.get("enable", "no")),
        "key_1": str(resource.get("key_1", "")),
        "ids": [str(resource.get("id", resource.get("name", "")))],
    }
    return PutGpoolRequest.model_validate(payload)


def _process_static_domain(
    device_info: DeviceInfo,
    domain_data: DataBase,
) -> Tuple[DataBase, List[str], bool]:
    auth = (device_info.username, device_info.password)
    record_fqdn = _ensure_fqdn(domain_data.name)

    query_response = dns_search_resources(
        RrsQueryParams(
            host=device_info.management_ip,
            search_attrs=[["name", "eq", record_fqdn, "and"]],
        ),
        auth=auth,
    )
    if not query_response.ok:
        return (
            domain_data,
            [_response_message("查询静态域名失败", query_response)],
            False,
        )

    resources = _parse_json_resources(query_response, "静态域名查询")
    if not resources:
        return domain_data, [f"未找到静态域名记录: {record_fqdn}"], False

    record_ids = _extract_resource_ids(resources)
    if not record_ids:
        return domain_data, [f"静态域名记录缺少可用 id: {record_fqdn}"], False

    update_response = put_rrs_record(
        PutRrsRequest(
            host=device_info.management_ip,
            ttl=domain_data.ttl or 60,
            ids=record_ids,
            _desc=_build_rrs_desc_map(resources),
        ),
        auth=auth,
    )
    messages = [
        f"静态域名匹配到 {len(record_ids)} 条记录",
        _response_message("修改静态域名 TTL 结果", update_response),
    ]
    return domain_data, messages, update_response.ok


def _process_dynamic_domain(
    device_info: DeviceInfo,
    domain_data: DataBase,
) -> Tuple[DataBase, List[str], bool]:
    auth = (device_info.username, device_info.password)
    record_fqdn = _ensure_fqdn(domain_data.name)
    zone_name = _build_dynamic_zone_name(domain_data.name)
    messages: List[str] = []

    query_response = get_gmap_record(
        GMapQueryParams(
            host=device_info.management_ip,
            zone=zone_name,
            search_attrs=[["name", "eq", record_fqdn, "and"]],
        ),
        auth=auth,
    )
    if not query_response.ok:
        return (
            domain_data,
            [_response_message("查询动态域名失败", query_response)],
            False,
        )

    resources = _parse_json_resources(query_response, "动态域名查询")
    if not resources:
        return domain_data, [f"未找到动态域名记录: {record_fqdn}"], False

    success = True

    if domain_data.algorithm is not None:
        for resource in resources:
            record_id = str(resource.get("id", "")).strip()
            if record_id == "":
                success = False
                messages.append(f"动态域名记录缺少可用 id: {record_fqdn}")
                continue

            update_response = put_gmap_record(
                PutGMapRequest(
                    host=device_info.management_ip,
                    zone=zone_name,
                    ids=[record_id],
                    algorithm=domain_data.algorithm,
                    enable=str(resource.get("enable", "yes")),
                ),
                auth=auth,
            )
            messages.append(
                _response_message(
                    f"修改动态域名算法结果[{record_id}]",
                    update_response,
                )
            )
            success = success and update_response.ok

    if domain_data.ttl is not None:
        pool_names: List[str] = []
        seen = set()
        for resource in resources:
            gpool_list = resource.get("gpool_list", [])
            if not isinstance(gpool_list, list):
                continue
            for pool_item in gpool_list:
                if not isinstance(pool_item, dict):
                    continue
                pool_name = str(pool_item.get("gpool_name", "")).strip()
                if pool_name == "" or pool_name in seen:
                    continue
                seen.add(pool_name)
                pool_names.append(pool_name)

        if not pool_names:
            messages.append(f"动态域名 {record_fqdn} 未关联地址池，无法修改 TTL")
            success = False
        else:
            pool_response = get_gpool(
                GpoolQueryParams(
                    host=device_info.management_ip,
                    pool_names=pool_names,
                ),
                auth=auth,
            )
            if not pool_response.ok:
                return (
                    domain_data,
                    messages + [_response_message("查询关联地址池失败", pool_response)],
                    False,
                )

            pool_resources = _parse_json_resources(pool_response, "地址池查询")
            pool_map = {
                str(resource.get("name", "")).strip(): resource
                for resource in pool_resources
                if str(resource.get("name", "")).strip() != ""
            }

            for pool_name in pool_names:
                pool_resource = pool_map.get(pool_name)
                if pool_resource is None:
                    success = False
                    messages.append(f"未找到关联地址池: {pool_name}")
                    continue

                put_request = _build_put_gpool_request(
                    pool_resource,
                    domain_data.ttl,
                    device_info.management_ip,
                )
                put_response = put_gpool(put_request, auth=auth)
                messages.append(
                    _response_message(
                        f"修改关联地址池 TTL 结果[{pool_name}]",
                        put_response,
                    )
                )
                success = success and put_response.ok

    return domain_data, messages, success


def _normalize_items(items: Union[DataBase, List[DataBase]]) -> List[DataBase]:
    if isinstance(items, list):
        return items
    return [items]


def modify_domain(data: Dict[str, Any]) -> ModifyDomainResponse:
    try:
        request = ModifyDomainRequest.model_validate(data)
        _log_step("modify_domain", "输入参数校验通过")
    except ValidationError as exc:
        _log_exception("modify_domain", "输入参数校验失败")
        return ModifyDomainResponse(
            success=False,
            message=[f"输入参数校验失败: {exc}"],
        )

    items = _normalize_items(request.data)
    results: List[DataBase] = []
    messages: List[str] = []
    success = True

    for item in items:
        try:
            if item.type == "static":
                result_item, item_messages, item_success = _process_static_domain(
                    request.device_info,
                    item,
                )
            else:
                result_item, item_messages, item_success = _process_dynamic_domain(
                    request.device_info,
                    item,
                )
        except (requests.RequestException, ValueError) as exc:
            _log_exception("modify_domain", f"处理域名 {item.name} 失败")
            result_item, item_messages, item_success = item, [str(exc)], False

        results.append(result_item)
        messages.extend([f"{item.name}: {message}" for message in item_messages])
        success = success and item_success

    return ModifyDomainResponse(
        success=success,
        result=results,
        message=messages,
    )


def main() -> int:
    input_path = (
        sys.argv[1] if len(sys.argv) > 1 else _default_input_path("modify_domain.json")
    )
    _log_step("main", "脚本启动", input_path=input_path, log_file=LOG_FILE)

    try:
        input_data = _load_input_data(input_path)
    except (OSError, json.JSONDecodeError) as exc:
        _log_exception("main", f"读取输入文件失败: {input_path}")
        _print_cli_error(f"读取输入文件失败: {exc}")
        return 1

    response = modify_domain(input_data)
    _log_step("main", "脚本执行完成", success=response.success)
    _print_cli_result(response)
    return 0 if response.success else 1


if __name__ == "__main__":
    sys.exit(main())
