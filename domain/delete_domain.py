import json
import logging
import os
from urllib.parse import quote
import requests
import urllib3
import sys
from typing import List, Dict, Any, Optional, Literal, Union, Tuple, Annotated
from pydantic import BaseModel, ConfigDict, Field, ValidationError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)

#############################################################
### 日志配置 ###

LOG_LEVEL = os.getenv("AUTOZDNS_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

logger = logging.getLogger("autozdns.delete_domain")


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


#############################################################
### 公共方法 ###


def _build_dns_search_query(search_attrs: List[List[str]]) -> str:
    query_parts: List[str] = []

    for index, attrs in enumerate(search_attrs):
        key = f"search_key[{index}][]"
        for attr in attrs:
            query_parts.append(f"{key}={quote(str(attr), safe='[]')}")

    return "&".join(query_parts)


#############################################################
### 标准输入规范 ###


class DeviceInfo(BaseModel):
    management_ip: str = Field(..., description="管理节点 IP")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


class DataBase(BaseModel):
    name: str = Field(..., description="域名")
    type: str = Field(..., description="静态动态类别，如 static 或 dynamic")


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
    pld: GMapQueryParams, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    动态域名解析查询记录
    通过 ZDNS API 查询 GMap (全局映射) 记录。
    """

    payload = pld.model_dump(by_alias=True, exclude_none=True)
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
        "准备发送 Get 请求",
        url=request_url,
        zone=zone_value,
    )

    response = requests.get(request_url, headers=headers, verify=verify_ssl, auth=auth)
    _log_http_response("get_gmap_record", response)
    return response


#############################################################
### API: 动态域名删除 ###


class GMapRequest(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图必须是 ADD")
    zone: str = Field(..., description="域名区")
    ids: List[str] = Field(..., description="记录 ID 列表")


def delete_gmap_record(
    req: GMapRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    动态域名解析删除记录
    通过 ZDNS API 删除 GMap (全局映射) 记录。

    """

    payload = req.model_dump(by_alias=True, exclude_none=True)
    # 不属于 payload 的字段需在请求前剔除
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
        "准备发送 GMap 请求",
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
    """
    静态域名解析查询资源
    通过 ZDNS API 查询 RRS (资源记录集) 记录。
    """
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
        "dns search resources",
        "准备发送 DNS 查询请求",
        url=request_url,
        search_attrs=search_attrs,
    )

    response = requests.get(request_url, headers=headers, verify=verify_ssl, auth=auth)
    _log_http_response("dns search resources", response)
    return response


"""
下方为查询结果范例，实际结果会根据查询条件不同而有所差异，主要用于展示数据结构和字段含义。
{
    "resources": [
        {
            "name": "www.wzw.com.",
            "type": "A",
            "klass": "IN",
            "ttl": 60,
            "rdata": "10.10.10.12",
            "reverse_name": "com.wzw.www",
            "is_enable": "yes",
            "row_id": 13,
            "comment": null,
            "audit_status": "",
            "expire_time": "",
            "expire_style": "",
            "create_time": "2026-04-15 15:24:42",
            "expire_is_enable": "no",
            "href": "/views/default/zones/wzw.com/rrs/A$13$default$wzw.com",
            "id": "A$13$default$wzw.com",
            "view_name": "default",
            "zone_name": "wzw.com",
            "members": [
                "local.master",
                "local.ft",
                "local.yz",
                "local.hf"
            ],
            "is_shared": "",
            "apply_user": null
        },
        {
            "name": "www.wzw.com.",
            "type": "A",
            "klass": "IN",
            "ttl": 60,
            "rdata": "10.10.10.13",
            "reverse_name": "com.wzw.www",
            "is_enable": "yes",
            "row_id": 14,
            "comment": null,
            "audit_status": "",
            "expire_time": "",
            "expire_style": "",
            "create_time": "2026-04-15 15:24:42",
            "expire_is_enable": "no",
            "href": "/views/default/zones/wzw.com/rrs/A$14$default$wzw.com",
            "id": "A$14$default$wzw.com",
            "view_name": "default",
            "zone_name": "wzw.com",
            "members": [
                "local.master",
                "local.ft",
                "local.yz",
                "local.hf"
            ],
            "is_shared": "",
            "apply_user": null
        },
        {
            "name": "www.wzw.com.",
            "type": "AAAA",
            "klass": "IN",
            "ttl": 60,
            "rdata": "2001:db8::1",
            "reverse_name": "com.wzw.www",
            "is_enable": "yes",
            "row_id": 15,
            "comment": null,
            "audit_status": "",
            "expire_time": "",
            "expire_style": "",
            "create_time": "2026-04-15 15:24:42",
            "expire_is_enable": "no",
            "href": "/views/default/zones/wzw.com/rrs/AAAA$15$default$wzw.com",
            "id": "AAAA$15$default$wzw.com",
            "view_name": "default",
            "zone_name": "wzw.com",
            "members": [
                "local.master",
                "local.ft",
                "local.yz",
                "local.hf"
            ],
            "is_shared": "",
            "apply_user": null
        },
        {
            "name": "www.wzw.com.",
            "type": "AAAA",
            "klass": "IN",
            "ttl": 60,
            "rdata": "2001:db8::2",
            "reverse_name": "com.wzw.www",
            "is_enable": "yes",
            "row_id": 16,
            "comment": null,
            "audit_status": "",
            "expire_time": "",
            "expire_style": "",
            "create_time": "2026-04-15 15:24:42",
            "expire_is_enable": "no",
            "href": "/views/default/zones/wzw.com/rrs/AAAA$16$default$wzw.com",
            "id": "AAAA$16$default$wzw.com",
            "view_name": "default",
            "zone_name": "wzw.com",
            "members": [
                "local.master",
                "local.ft",
                "local.yz",
                "local.hf"
            ],
            "is_shared": "",
            "apply_user": null
        }
    ],
    "page_num": 1,
    "page_size": 30,
    "total_size": 4,
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
}
"""


############################################################
### API: 静态域名删除 ###


class RrsRequestBase(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="主机 IP")
    is_enable: str = Field(..., description="是否启用")
    ids: List[str] = Field(..., description="记录 ID 列表")
    desc: Dict[str, str] = Field(
        ...,
        alias="_desc",
        serialization_alias="_desc",
        description="记录 ID 与描述的映射关系",
    )


"""
需要组成以下的字符串才可以用于删除记录，具体格式为 _desc[记录ID]=描述&ids[]=记录ID。下方为示例字符串，实际字符串会根据查询结果和删除需求不同而有所差异，主要用于展示数据结构和字段含义。
单个记录格式：
_desc[A$4$default$wzw.com]=www.wzw.com. A 10.10.10.13&link_ptr=no&link_cname=no&link_srv=no&link_mx=no&ids[]=A$4$default$wzw.com
多记录格式：
_desc[A$13$default$wzw.com]=default/[www.wzw.com](https://www.wzw.com).&_desc[A$14$default$wzw.com]=default/www.wzw.com.&_desc[AAAA$15$default$wzw.com]=default/[www.wzw.com](https://www.wzw.com).&_desc[AAAA$16$default$wzw.com]=default/www.wzw.com.&link_ptr=no&link_cname=no&link_srv=no&link_mx=no&ids[]=A$13$default$wzw.com&ids[]=A$14$default$wzw.com&ids[]=AAAA$15$default$wzw.com&ids[]=AAAA$16$default$wzw.com
"""


def delete_rrs_record(
    req: RrsRequestBase, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    静态域名解析删除记录
    通过 ZDNS API 删除 RRS (资源记录集) 记录。
    """

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
        "rrs",
        "准备发送 RRS 请求",
        url=url,
        record_ids=payload.get("ids"),
    )

    response = requests.delete(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("rrs", response)
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


def _process_delete_domain_item(
    device_info: DeviceInfo,
    domain_data: DataBase,
) -> DeleteDomainResponse:
    auth = (device_info.username, device_info.password)
    domain_name = domain_data.name.strip()
    domain_type = domain_data.type.strip().lower()
    record_fqdn = _ensure_fqdn(domain_name)

    _log_step(
        "delete-domain",
        "开始处理单个域名",
        domain_name=domain_name,
        domain_type=domain_type,
        record_fqdn=record_fqdn,
    )

    try:
        if domain_type == "dynamic":
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
                return _build_single_delete_domain_response(
                    success=False,
                    result=domain_data,
                    message=[_response_message("查询动态域名失败", query_response)],
                )

            payload, payload_error = _parse_response_json(
                query_response, "delete-domain"
            )
            if payload_error:
                return _build_single_delete_domain_response(
                    success=False,
                    result=domain_data,
                    message=[payload_error],
                )

            payload = payload or {}
            resources = payload.get("resources", [])
            if not isinstance(resources, list) or not resources:
                return _build_single_delete_domain_response(
                    success=False,
                    result=domain_data,
                    message=[f"未找到可删除的动态域名记录: {record_fqdn}"],
                )

            record_ids = _extract_resource_ids(resources)
            if not record_ids:
                return _build_single_delete_domain_response(
                    success=False,
                    result=domain_data,
                    message=[f"动态域名记录缺少可用 id: {record_fqdn}"],
                )

            delete_response = delete_gmap_record(
                GMapRequest(
                    host=device_info.management_ip,
                    zone=zone_name,
                    ids=record_ids,
                ),
                auth=auth,
            )
            return _build_single_delete_domain_response(
                success=delete_response.ok,
                result=domain_data,
                message=[
                    f"动态域名匹配到 {len(record_ids)} 条记录",
                    _response_message("删除动态域名结果", delete_response),
                ],
            )

        if domain_type == "static":
            query_response = dns_search_resources(
                RrsQueryParams(
                    host=device_info.management_ip,
                    search_attrs=[["name", "eq", record_fqdn, "and"]],
                ),
                auth=auth,
            )
            if not query_response.ok:
                return _build_single_delete_domain_response(
                    success=False,
                    result=domain_data,
                    message=[_response_message("查询静态域名失败", query_response)],
                )

            payload, payload_error = _parse_response_json(
                query_response, "delete-domain"
            )
            if payload_error:
                return _build_single_delete_domain_response(
                    success=False,
                    result=domain_data,
                    message=[payload_error],
                )

            payload = payload or {}
            resources = payload.get("resources", [])
            if not isinstance(resources, list) or not resources:
                return _build_single_delete_domain_response(
                    success=False,
                    result=domain_data,
                    message=[f"未找到可删除的静态域名记录: {record_fqdn}"],
                )

            record_ids = _extract_resource_ids(resources)
            if not record_ids:
                return _build_single_delete_domain_response(
                    success=False,
                    result=domain_data,
                    message=[f"静态域名记录缺少可用 id: {record_fqdn}"],
                )

            delete_response = put_rrs_record(
                RrsRequestBase(
                    host=device_info.management_ip,
                    is_enable="no",
                    ids=record_ids,
                    _desc=_build_rrs_desc_map(resources),
                ),
                auth=auth,
            )
            return _build_single_delete_domain_response(
                success=delete_response.ok,
                result=domain_data,
                message=[
                    f"静态域名匹配到 {len(record_ids)} 条记录",
                    _response_message("删除静态域名结果", delete_response),
                ],
            )

        return _build_single_delete_domain_response(
            success=False,
            result=domain_data,
            message=[f"不支持的域名类型: {domain_data.type}"],
        )
    except (ValidationError, ValueError) as error:
        _log_exception(
            "delete-domain", f"处理 delete_domain 时发生校验或值错误: {error}"
        )
        return _build_single_delete_domain_response(
            success=False,
            result=domain_data,
            message=[str(error)],
        )
    except requests.RequestException as error:
        _log_exception("delete-domain", f"处理 delete_domain 时发生请求异常: {error}")
        return _build_single_delete_domain_response(
            success=False,
            result=domain_data,
            message=[str(error)],
        )


def delete_domain(data: Dict[str, Any]) -> DeleteDomainResponse:
    """
    删除域名核心逻辑：
    1. 接收输入数据并验证格式
    2. 根据输入数据类型分别调用不同的查询方法查询当前域名记录
    3. 根据查询结果和输入数据确定需要删除的记录 ID 列表
    4. 构造删除请求并发送删除 API 请求
    5. 处理删除 API 响应并返回结果
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请提供 JSON 文件路径")
        sys.exit(1)

    input_json = sys.argv[1]
    with open(input_json, "r", encoding="utf-8") as file:
        input_data = json.load(file)

    result = delete_domain(input_data)
    print("\n******* Delete Domain Result *******")
    print(result.model_dump_json(indent=2, ensure_ascii=False))
