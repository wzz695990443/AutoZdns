import json
import logging
import os
import requests
import urllib3
import sys
from typing import List, Dict, Any, Literal, Tuple
from urllib.parse import quote

from pydantic import BaseModel, Field, ValidationError, ConfigDict, model_validator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)

#############################################################
### 日志配置 ###

LOG_LEVEL = os.getenv("AUTOZDNS_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("autozdns.delete_record")


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
### 标准输入规范 ###


class DeviceInfo(BaseModel):
    management_ip: str = Field(..., description="管理节点 IP")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


class DataBase(BaseModel):
    name: str = Field(..., description="IP地址+端口,例如1.1.1.1_443")
    value: str = Field(..., description="IP")
    enabled: bool = Field(default=False, description="是否已删除")
    domain_names: List[str] = Field(default_factory=list, description="关联的域名列表")
    pool_names: List[str] = Field(default_factory=list, description="关联的地址池列表")

    @model_validator(mode="after")
    def normalize_values(self) -> "DataBase":
        self.name = self.name.strip()
        self.value = self.value.strip()
        self.domain_names = [
            item.strip() for item in self.domain_names if item.strip() != ""
        ]
        self.pool_names = [
            item.strip() for item in self.pool_names if item.strip() != ""
        ]
        return self


class DeleteRecordRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["delete_record"] = Field(..., description="操作类型")
    data: List[DataBase] = Field(..., description="要删除的记录列表")


#############################################################
### 标准输出规范 ###


class DeleteRecordResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: List[DataBase] = Field(default_factory=list, description="操作结果数据")
    message: List[str] = Field(default_factory=list, description="操作结果消息")


#############################################################
### API: 删除地址池成员 ###


class DeleteGpoolgmemberRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="主机 IP")
    pool: str = Field(..., description="地址池名称")
    ids: List[str] = Field(..., description="记录 ID 列表")
    desc: Dict[str, str] = Field(
        ...,
        alias="_desc",
        serialization_alias="_desc",
        description="记录 ID 与描述的映射关系",
    )


def _encode_form_value(value: Any) -> str:
    return quote(str(value), safe="")


def _build_gpoolgmember_delete_body(
    req: DeleteGpoolgmemberRequest,
) -> Tuple[str, str, str]:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = str(payload.pop("host", ""))
    pool_value = str(payload.pop("pool", ""))
    desc_map = payload.get("_desc", {})
    record_ids = payload.get("ids", [])

    body_parts: List[str] = []
    for record_id in record_ids:
        record_id_text = str(record_id)
        desc_text = str(desc_map.get(record_id_text, ""))
        body_parts.append(f"_desc[{record_id_text}]={_encode_form_value(desc_text)}")

    for record_id in record_ids:
        body_parts.append(f"ids[]={_encode_form_value(record_id)}")

    return host_value, pool_value, "&".join(body_parts)


def delete_gpoolgmember(
    req: DeleteGpoolgmemberRequest,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    host_value, pool_value, body_string = _build_gpoolgmember_delete_body(req)
    url = f"https://{host_value}:20120/gpool/{pool_value}/gpoolgmember"

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
        "delete_gpoolgmember",
        "准备发送地址池成员删除请求",
        url=url,
        pool=pool_value,
        body_preview=body_string[:300],
    )

    response = requests.delete(
        url,
        headers=headers,
        data=body_string,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("delete_gpoolgmember", response)
    return response


#############################################################
### API: 动态域名查询 ###


class GMapQueryParams(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图必须是 ADD")
    zone: str = Field(..., description="域名区")
    search_attrs: List[List[str]] = Field(..., description="搜索属性嵌套列表")
    version: int = Field(default=2, description="接口版本")


def _build_dns_search_query(search_attrs: List[List[str]], version: int = 2) -> str:
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
    query_string = _build_dns_search_query(req.search_attrs, req.version)
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


#############################################################
### API: 查询地址池 ###


class GpoolParamsBase(BaseModel):
    host: str = Field(..., description="设备管理IP")
    pool_names: List[str] = Field(..., description="地址池名称列表")
    version: str = Field(default="2", description="API版本")


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
        "准备发送查询地址池请求",
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
### 删除地址池成员记录核心逻辑 ###


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


def _dedupe_strings(values: List[str]) -> List[str]:
    result: List[str] = []
    seen = set()

    for value in values:
        normalized = value.strip()
        if normalized == "" or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)

    return result


def _query_domain_related_pool_names(
    device_info: DeviceInfo,
    domain_names: List[str],
    auth: tuple,
) -> Tuple[List[str], List[str], bool]:
    messages: List[str] = []
    pool_names: List[str] = []
    had_error = False

    for domain_name in _dedupe_strings(domain_names):
        try:
            zone_name = _build_dynamic_zone_name(domain_name)
            fqdn = _ensure_fqdn(domain_name)
        except ValueError as exc:
            messages.append(f"域名 {domain_name}: {exc}")
            continue

        try:
            response = get_gmap_record(
                GMapQueryParams(
                    host=device_info.management_ip,
                    zone=zone_name,
                    search_attrs=[["name", "eq", fqdn, "and"]],
                ),
                auth=auth,
            )
        except requests.RequestException as exc:
            _log_exception("delete_record", "查询动态域名失败")
            messages.append(f"域名 {domain_name}: 查询动态域名请求失败: {exc}")
            had_error = True
            continue

        if not response.ok:
            messages.append(
                f"域名 {domain_name}: 查询动态域名失败, status={response.status_code}, body={response.text[:200]}"
            )
            had_error = True
            continue

        try:
            resources = _parse_json_resources(response, "动态域名查询")
        except ValueError as exc:
            _log_exception("delete_record", "解析动态域名查询结果失败")
            messages.append(f"域名 {domain_name}: {exc}")
            had_error = True
            continue

        if not resources:
            messages.append(f"域名 {domain_name}: 未找到动态域名记录")
            continue

        domain_pool_names: List[str] = []
        for resource in resources:
            gpool_list = resource.get("gpool_list", [])
            if not isinstance(gpool_list, list):
                continue

            for pool_item in gpool_list:
                if not isinstance(pool_item, dict):
                    continue

                pool_name = str(pool_item.get("gpool_name", "")).strip()
                if pool_name != "":
                    domain_pool_names.append(pool_name)

        domain_pool_names = _dedupe_strings(domain_pool_names)
        if not domain_pool_names:
            messages.append(f"域名 {domain_name}: 未关联任何地址池")
            continue

        messages.append(f"域名 {domain_name}: 关联地址池 {domain_pool_names}")
        pool_names.extend(domain_pool_names)

    return _dedupe_strings(pool_names), messages, had_error


def _query_pools_by_names(
    device_info: DeviceInfo,
    pool_names: List[str],
    auth: tuple,
) -> Tuple[Dict[str, Dict[str, Any]], List[str], bool]:
    normalized_pool_names = _dedupe_strings(pool_names)
    if not normalized_pool_names:
        return {}, ["未提供有效的地址池名称"], False

    try:
        response = get_gpool(
            GpoolParamsBase(
                host=device_info.management_ip,
                pool_names=normalized_pool_names,
            ),
            auth=auth,
        )
    except requests.RequestException as exc:
        _log_exception("delete_record", "查询地址池失败")
        return {}, [f"查询地址池请求失败: {exc}"], True

    if not response.ok:
        return (
            {},
            [
                f"查询地址池失败, status={response.status_code}, body={response.text[:200]}"
            ],
            True,
        )

    try:
        resources = _parse_json_resources(response, "地址池查询")
    except ValueError as exc:
        _log_exception("delete_record", "解析地址池查询结果失败")
        return {}, [str(exc)], True

    pool_map: Dict[str, Dict[str, Any]] = {}
    for resource in resources:
        pool_name = str(resource.get("name", "")).strip()
        if pool_name != "":
            pool_map[pool_name] = resource

    messages = [
        f"未找到地址池: {pool_name}"
        for pool_name in normalized_pool_names
        if pool_name not in pool_map
    ]
    return pool_map, messages, False


def _member_matches(member: Dict[str, Any], item: DataBase) -> bool:
    member_name = str(member.get("gmember_name", "")).strip()
    member_ip = str(member.get("ip", "")).strip()
    return member_name == item.name and member_ip == item.value


def _build_delete_gpoolgmember_request(
    host: str,
    pool_name: str,
    member: Dict[str, Any],
) -> DeleteGpoolgmemberRequest:
    member_id = str(member.get("id", "")).strip()
    dc_name = str(member.get("dc_name", "")).strip()
    gmember_name = str(member.get("gmember_name", "")).strip()

    if member_id == "":
        if dc_name == "" or gmember_name == "":
            raise ValueError("地址池成员缺少 id 或 dc_name/gmember_name")
        member_id = f"{dc_name}*{gmember_name}"

    desc_value = str(member.get("record", "")).strip()
    if desc_value == "":
        desc_value = str(member.get("name", "")).strip() or member_id

    return DeleteGpoolgmemberRequest(
        host=host,
        pool=pool_name,
        ids=[member_id],
        _desc={member_id: desc_value},
    )


def _find_matching_members(
    pool_map: Dict[str, Dict[str, Any]],
    item: DataBase,
) -> List[Tuple[str, Dict[str, Any]]]:
    matches: List[Tuple[str, Dict[str, Any]]] = []

    for pool_name, pool_resource in pool_map.items():
        members = pool_resource.get("gmember_list", [])
        if not isinstance(members, list):
            continue

        for member in members:
            if isinstance(member, dict) and _member_matches(member, item):
                matches.append((pool_name, member))

    return matches


def _process_delete_record_item(
    device_info: DeviceInfo,
    item: DataBase,
) -> Tuple[DataBase, List[str], bool]:
    auth = (device_info.username, device_info.password)
    messages: List[str] = []
    had_error = False

    if item.pool_names:
        target_pool_names = _dedupe_strings(item.pool_names)
        if item.domain_names:
            messages.append(f"{item.name}: 已提供 pool_names，忽略 domain_names")
    elif item.domain_names:
        target_pool_names, domain_messages, domain_error = (
            _query_domain_related_pool_names(
                device_info,
                item.domain_names,
                auth,
            )
        )
        messages.extend([f"{item.name}: {message}" for message in domain_messages])
        had_error = had_error or domain_error
    else:
        updated_item = item.model_copy(update={"enabled": False})
        return (
            updated_item,
            [f"{item.name}: domain_names 和 pool_names 不能同时为空"],
            False,
        )

    if not target_pool_names:
        updated_item = item.model_copy(update={"enabled": False})
        if not messages:
            messages.append(f"{item.name}: 未解析出可处理的地址池")
        return updated_item, messages, False

    pool_map, pool_messages, pool_error = _query_pools_by_names(
        device_info,
        target_pool_names,
        auth,
    )
    messages.extend([f"{item.name}: {message}" for message in pool_messages])
    had_error = had_error or pool_error

    matched_members = _find_matching_members(pool_map, item)
    if not matched_members:
        updated_item = item.model_copy(update={"enabled": False})
        messages.append(
            f"{item.name}: 未在目标地址池中找到 name={item.name}, value={item.value} 的成员记录"
        )
        return updated_item, messages, False

    for pool_name, member in matched_members:
        member_name = str(member.get("gmember_name", "")).strip() or item.name

        try:
            request_payload = _build_delete_gpoolgmember_request(
                device_info.management_ip,
                pool_name,
                member,
            )
        except ValueError as exc:
            had_error = True
            messages.append(
                f"{item.name}: 地址池 {pool_name} 成员 {member_name} 请求构造失败: {exc}"
            )
            continue

        try:
            response = delete_gpoolgmember(request_payload, auth=auth)
        except requests.RequestException as exc:
            _log_exception("delete_record", "调用 delete_gpoolgmember 失败")
            had_error = True
            messages.append(
                f"{item.name}: 地址池 {pool_name} 成员 {member_name} 删除请求失败: {exc}"
            )
            continue

        if response.ok:
            messages.append(
                f"{item.name}: 地址池 {pool_name} 成员 {member_name} 删除成功"
            )
            continue

        had_error = True
        messages.append(
            f"{item.name}: 地址池 {pool_name} 成员 {member_name} 删除失败, status={response.status_code}, body={response.text[:200]}"
        )

    item_success = bool(matched_members) and not had_error
    updated_item = item.model_copy(update={"enabled": item_success})
    return updated_item, messages, item_success


def delete_record(data: Dict[str, Any]) -> DeleteRecordResponse:
    try:
        request_data = DeleteRecordRequest.model_validate(data)
        _log_step(
            "delete_record",
            "输入参数校验通过",
            record_count=len(request_data.data),
        )
    except ValidationError as exc:
        _log_exception("delete_record", "输入参数校验失败")
        return DeleteRecordResponse(success=False, message=[f"输入参数校验失败: {exc}"])

    result: List[DataBase] = []
    messages: List[str] = []
    all_success = True

    for item in request_data.data:
        updated_item, item_messages, item_success = _process_delete_record_item(
            request_data.device_info,
            item,
        )
        result.append(updated_item)
        messages.extend(item_messages)
        all_success = all_success and item_success

    return DeleteRecordResponse(
        success=all_success,
        result=result,
        message=messages,
    )


if __name__ == "__main__":
    input_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(os.path.dirname(__file__), "input", "delete_record.json")
    )

    with open(input_path, "r", encoding="utf-8") as file:
        input_data = json.load(file)

    response = delete_record(input_data)
    print("\n******* Delete Record Result *******")
    print(json.dumps(response.model_dump(), ensure_ascii=False, indent=4))
