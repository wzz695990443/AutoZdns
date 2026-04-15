import ipaddress
import json
import logging
import os
import requests
import urllib3
import sys
from typing import List, Dict, Any, Optional, Literal, Union, Tuple, Annotated
from pydantic import BaseModel, Field, ValidationError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)

#############################################################
### 日志配置 ###

LOG_LEVEL = os.getenv("AUTOZDNS_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("autozdns.add_domain")


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


class StaticRecord(BaseModel):
    name: str = Field(default="", description="记录名称")
    type: str = Field(..., description="记录类型")
    value: str = Field(..., description="记录值")


class DomainPoolRef(BaseModel):
    name: str = Field(..., description="地址池名称")


class DynamicDomainInfo(BaseModel):
    name: str = Field(..., description="域名")
    type: Literal["dynamic"] = Field(default="dynamic", description="域名解析方式")
    algorithm: str = Field(default="rr", description="域名算法")
    ttl: int = Field(..., description="TTL")
    pools: List[DomainPoolRef] = Field(..., description="地址池列表")


class StaticDomainInfo(BaseModel):
    name: str = Field(..., description="域名")
    type: Literal["static"] = Field(default="static", description="域名解析方式")
    ttl: int = Field(..., description="TTL")
    records: List[StaticRecord] = Field(..., description="记录列表")


class AddDomainRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["add_domain"] = Field(..., description="操作类型")
    data: Annotated[
        Union[DynamicDomainInfo, StaticDomainInfo],
        Field(discriminator="type"),
    ]


#############################################################
### 标准输出规范 ###

DomainResult = Annotated[
    Union[DynamicDomainInfo, StaticDomainInfo],
    Field(discriminator="type"),
]


class AddDomainResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: Optional[DomainResult] = Field(default=None, description="返回的域名信息")
    message: List[str] = Field(..., description="操作结果消息")


#############################################################
### API: ADD 视图增加域名 ###


class GPoolItem(BaseModel):
    gpool_name: str
    ratio: str = Field(default="1", description="权重")


class GMapRequest(BaseModel):
    # 下列字段为必填项 (不提供默认值)
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图必须是 ADD")
    zone: str = Field(..., description="域名区")
    name: str = Field(..., description="完整记录名")
    type: str = Field(..., alias="type", description="记录类型")
    algorithm: str = Field(..., description="负载均衡算法")
    fail_policy: str = Field(..., description="失败应答策略")
    enable: str = Field(..., description="是否启用")

    # 下列字段为选填项 (显式写出 default= 以兼容 VS Code 的静态检查)
    gpool_list: List[GPoolItem] = Field(
        default_factory=list, description="全局地址池列表"
    )
    failure_response_rrs_ttl: int = Field(default=5, description="缓存 TTL")
    failure_response_soa_ttl: int = Field(default=5, description="否定缓存 TTL")
    last_resort_pool: Optional[str] = Field(default="", description="备份 pool")
    key_1: Optional[str] = Field(default="", description="备注")


def post_gmap_record(
    req: GMapRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    动态域名解析增加记录
    通过 ZDNS API 创建或修改 GMap (全局映射) 记录。
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
        "gmap",
        "准备发送 GMap 请求",
        url=url,
        zone=zone_value,
        name=payload.get("name"),
        record_type=payload.get("type"),
        algorithm=payload.get("algorithm"),
        pool_count=len(payload.get("gpool_list", [])),
    )

    response = requests.post(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("gmap", response)
    return response


############################################################
### API: default 视图增加域名 ###


class RdataItem(BaseModel):
    value: str


class RrsRequest(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: str = Field(..., description="视图")
    zone: str = Field(..., description="域名区 (Zone)")
    name: str = Field(..., description="完整记录名 (如 www.test.com.)")
    type: str = Field(..., alias="type", description="记录类型")
    ttl: int = Field(default=3600, description="TTL")
    rdata: List[str] = Field(..., description="记录值")
    link_ptr: Optional[str] = Field(default="no", description="自动关联 PTR 记录名称")
    expire_is_enable: str = Field(default="no", description="是否启用过期记录")
    is_enable: str = Field(default="yes", description="是否启用")


def post_rrs_record(
    req: RrsRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    静态域名解析增加记录
    通过 ZDNS API 创建或修改 RRS (资源记录集) 记录。
    """

    payload = req.model_dump(by_alias=True, exclude_none=True)
    # 不属于 payload 的字段需在请求前剔除
    host_value = payload.pop("host", None)
    view_value = payload.pop("view", None)
    zone_value = payload.pop("zone", None)

    url = f"https://{host_value}:20120/views/{view_value}/zones/{zone_value}/rrs"

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
        "post rrs",
        "准备发送 RRS 请求",
        url=url,
        zone=zone_value,
        name=payload.get("name"),
        record_type=payload.get("type"),
        ttl=payload.get("ttl"),
        rdata_count=len(payload.get("rdata", [])),
    )

    response = requests.post(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("rrs", response)
    return response


#############################################################
### API: 获取地址池 ###


class GPoolInfo(BaseModel):
    name: str = Field(..., description="地址池名称")
    type: str = Field(..., description="地址池类型")


def get_gpool_list(req: DeviceInfo) -> List[GPoolInfo]:
    url = f"https://{req.management_ip}:20120/gpool_list"
    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{req.management_ip}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }

    _log_step(
        "gpool",
        "准备获取地址池列表",
        url=url,
        management_ip=req.management_ip,
        username=req.username,
    )

    try:
        response = requests.get(
            url,
            headers=headers,
            verify=False,
            auth=(req.username, req.password),
            # timeout=10,
        )
    except requests.RequestException as error:
        _log_exception("gpool", f"获取地址池列表请求失败: {error}")
        return []

    if not response.ok:
        _log_http_response("gpool", response)
        return []

    content_type = response.headers.get("Content-Type", "")
    if "json" not in content_type.lower():
        _log_http_response("gpool", response)
        _log_step("gpool", "地址池接口返回的不是 JSON")
        return []

    try:
        response_data = response.json()
    except requests.exceptions.JSONDecodeError:
        _log_http_response("gpool", response)
        _log_step("gpool", "地址池接口返回内容无法解析为 JSON")
        return []

    if not isinstance(response_data, list):
        _log_step("gpool", "地址池接口返回格式异常", response_data=response_data)
        return []

    parsed_gpools = [GPoolInfo.model_validate(item) for item in response_data]
    _log_step(
        "gpool",
        "地址池列表解析完成",
        total=len(parsed_gpools),
        pools=[{"name": pool.name, "type": pool.type} for pool in parsed_gpools],
    )
    return parsed_gpools


#############################################################
### 增加域名核心逻辑 ###


def _ensure_fqdn(name: str) -> str:
    """
    确保域名以点号结尾，符合 FQDN 规范。
    """
    return name if name.endswith(".") else f"{name}."


def _build_dynamic_zone_name(name: str) -> str:
    """
    构建动态域名的区域名称。
    """
    fqdn = _ensure_fqdn(name).rstrip(".")
    labels = fqdn.split(".")
    if len(labels) < 2:
        raise ValueError(f"非法域名: {name}")
    return f"{labels[-2]}.{labels[-1]}."


def _build_static_zone_name(name: str) -> str:
    """
    构建静态域名的区域名称。
    """

    fqdn = _ensure_fqdn(name).rstrip(".")
    labels = fqdn.split(".")
    if len(labels) < 2:
        raise ValueError(f"非法域名: {name}")
    return f"{labels[-2]}.{labels[-1]}"


def _build_record_name(record_name: str, domain_name: str) -> str:
    """
    构建完整的记录名称，确保符合 FQDN 规范。
    规则说明：
    1. 如果记录名称为空或为 "@", 则使用域名作为记录名称。
    2. 如果记录名称以点号结尾，认为已经是 FQDN，直接使用。
    3. 如果记录名称等于域名或域名的 FQDN 形式，则使用域名的 FQDN 形式。
    4. 如果记录名称以域名结尾，认为是相对域名，直接使用记录名称的 FQDN 形式。
    5. 其他情况，将记录名称和域名组合成一个新的 FQDN。
    """
    if record_name in {"", "@"}:
        return _ensure_fqdn(domain_name)
    if record_name.endswith("."):
        return record_name
    if record_name == domain_name or record_name == _ensure_fqdn(domain_name):
        return _ensure_fqdn(domain_name)
    if record_name.endswith(domain_name):
        return _ensure_fqdn(record_name)
    return _ensure_fqdn(f"{record_name}.{domain_name}")


def _resolve_record_type(record: StaticRecord) -> str:
    """
    根据记录类型和记录值解析最终的记录类型。
    规则说明：
    1. 如果记录类型已经是 A 或 AAAA，直接返回。
    2. 如果已经显式传入其他记录类型，如 CNAME、MX、TXT，直接返回原始类型。
    3. 仅当记录类型为空时，才根据记录值的 IP 版本确定记录类型，IPv4 返回 A，IPv6 返回 AAAA。
    """
    record_type = record.type.strip().upper()
    if record_type in {"A", "AAAA"}:
        return record_type

    if record_type:
        return record_type

    ip_version = ipaddress.ip_address(record.value).version
    return "A" if ip_version == 4 else "AAAA"


def _validate_dynamic_pools(
    device_info: DeviceInfo, pools: List[DomainPoolRef]
) -> Tuple[Optional[str], Dict[str, List[str]]]:
    """
    校验动态域名地址池的有效性。
    规则说明：
    1. 获取地址池列表，如果为空，返回错误信息。
    2. 检查输入的地址池是否存在，不存在的地址池返回错误信息。
    3. 根据地址池类型分组，仅支持 A 和 AAAA 类型。
    4. 如果没有可用的 A 或 AAAA 地址池，返回错误信息。
    """

    _log_step(
        "dynamic-pool",
        "开始校验动态域名地址池",
        requested_pools=[pool.name for pool in pools],
    )
    gpool_list = get_gpool_list(device_info)
    if not gpool_list:
        _log_step("dynamic-pool", "地址池列表为空，结束校验")
        return "获取地址池列表失败或返回为空。", {}

    pool_type_mapping = {pool.name: pool.type.upper() for pool in gpool_list}
    input_pool_names = [pool.name for pool in pools]

    missing_pools = [
        pool_name
        for pool_name in input_pool_names
        if pool_name not in pool_type_mapping
    ]
    if missing_pools:
        _log_step("dynamic-pool", "发现不存在的地址池", missing_pools=missing_pools)
        return f"以下地址池不存在: {', '.join(missing_pools)}", {}

    grouped_pools: Dict[str, List[str]] = {"A": [], "AAAA": []}
    unsupported_pools: List[str] = []
    for pool_name in input_pool_names:
        pool_type = pool_type_mapping[pool_name]
        if pool_type in grouped_pools:
            grouped_pools[pool_type].append(pool_name)
        else:
            unsupported_pools.append(f"{pool_name}({pool_type})")

    if unsupported_pools:
        _log_step(
            "dynamic-pool",
            "发现不支持的地址池类型",
            unsupported_pools=unsupported_pools,
        )
        return (
            f"以下地址池类型不受支持，仅支持 A/AAAA: {', '.join(unsupported_pools)}",
            {},
        )

    if not grouped_pools["A"] and not grouped_pools["AAAA"]:
        _log_step("dynamic-pool", "没有可用的 A 或 AAAA 地址池")
        return "未匹配到可用的 A 或 AAAA 地址池。", {}

    _log_step("dynamic-pool", "动态域名地址池校验通过", grouped_pools=grouped_pools)
    return None, grouped_pools


def _build_add_domain_response(
    success: bool,
    message: List[str],
    result: Optional[Union[DynamicDomainInfo, StaticDomainInfo]] = None,
) -> AddDomainResponse:
    return AddDomainResponse(success=success, result=result, message=message)


def _build_static_view_name(domain_name: str) -> str:
    return "default"


def add_domain(data: Dict[str, Any]) -> AddDomainResponse:
    """
    添加域名记录
    逻辑说明：
    1. 验证输入数据结构和内容。
    2. 根据域名类型（dynamic 或 static）执行不同的处理流程。
    3. 对于 dynamic 域名，验证关联的地址池是否存在且类型正确，然后调用 post_gmap_record 创建 GMap 记录。
    4. 对于 static 域名，构建完整记录名称并调用 post_rrs_record 创建 RRS 记录。
    5. 捕获并返回任何验证错误或请求异常，确保函数的健壮性。

    """
    _log_step("add-domain", "开始处理 add_domain 请求", input_data=data)

    try:
        request = AddDomainRequest.model_validate(data)
    except ValidationError as error:
        _log_step("add-domain", "输入校验失败", errors=error.errors())
        return _build_add_domain_response(
            success=False,
            message=[error.json(indent=2)],
        )

    auth = (request.device_info.username, request.device_info.password)
    record_fqdn = _ensure_fqdn(request.data.name)
    dynamic_zone_name = _build_dynamic_zone_name(request.data.name)
    static_zone_name = _build_static_zone_name(request.data.name)
    static_view_name = _build_static_view_name(request.data.name)
    _log_step(
        "add-domain",
        "输入校验成功",
        domain_type=request.data.type,
        record_fqdn=record_fqdn,
        dynamic_zone_name=dynamic_zone_name,
        static_zone_name=static_zone_name,
    )

    try:
        if isinstance(request.data, DynamicDomainInfo):
            _log_step(
                "add-domain",
                "进入 dynamic 域名处理分支",
                domain_name=request.data.name,
                ttl=request.data.ttl,
                algorithm=request.data.algorithm,
            )
            pool_error, grouped_pools = _validate_dynamic_pools(
                request.device_info,
                request.data.pools,
            )
            if pool_error:
                _log_step("add-domain", "动态域名地址池校验失败", error=pool_error)
                return _build_add_domain_response(
                    success=False,
                    result=request.data,
                    message=[pool_error],
                )

            responses: List[str] = []
            success = True
            for record_type, pool_names in grouped_pools.items():
                if not pool_names:
                    continue

                _log_step(
                    "add-domain",
                    "准备发送动态域名请求",
                    record_type=record_type,
                    pool_names=pool_names,
                )

                gmap_request = GMapRequest(
                    host=request.device_info.management_ip,
                    zone=dynamic_zone_name,
                    name=record_fqdn,
                    type=record_type,
                    algorithm=request.data.algorithm,
                    fail_policy="return_add_rrs",
                    enable="yes",
                    gpool_list=[
                        GPoolItem(gpool_name=pool_name) for pool_name in pool_names
                    ],
                    failure_response_rrs_ttl=5,
                    failure_response_soa_ttl=5,
                )
                response = post_gmap_record(req=gmap_request, auth=auth)
                response_text = response.text.strip() or "无返回内容"
                responses.append(
                    f"dynamic {record_type}: {response.status_code} - {response_text}"
                )
                if not response.ok:
                    success = False

            _log_step(
                "add-domain",
                "dynamic 域名处理完成",
                success=success,
                responses=responses,
            )
            return _build_add_domain_response(
                success=success,
                result=request.data,
                message=responses,
            )

        _log_step(
            "add-domain",
            "进入 static 域名处理分支",
            domain_name=request.data.name,
            ttl=request.data.ttl,
            record_count=len(request.data.records),
        )
        grouped_records: Dict[tuple[str, str], List[str]] = {}
        for record in request.data.records:
            record_type = _resolve_record_type(record)
            record_name = _build_record_name(record.name, request.data.name)
            grouped_records.setdefault((record_name, record_type), []).append(
                record.value
            )

        _log_step(
            "add-domain",
            "static 记录分组完成",
            grouped_records={
                f"{record_name}|{record_type}": record_values
                for (record_name, record_type), record_values in grouped_records.items()
            },
        )

        responses: List[str] = []
        success = True
        for (record_name, record_type), record_values in grouped_records.items():
            _log_step(
                "add-domain",
                "准备发送静态域名请求",
                record_name=record_name,
                record_type=record_type,
                record_values=record_values,
            )
            rrs_request = RrsRequest(
                host=request.device_info.management_ip,
                view=static_view_name,
                zone=static_zone_name,
                name=record_name,
                type=record_type,
                ttl=request.data.ttl,
                rdata=record_values,
            )
            response = post_rrs_record(req=rrs_request, auth=auth)
            response_text = response.text.strip() or "无返回内容"
            responses.append(
                f"{record_name} {record_type}: {response.status_code} - {response_text}"
            )
            if not response.ok:
                success = False

        _log_step(
            "add-domain",
            "static 域名处理完成",
            success=success,
            responses=responses,
        )
        return _build_add_domain_response(
            success=success,
            result=request.data,
            message=responses,
        )
    except (ValidationError, ValueError) as error:
        _log_exception("add-domain", f"处理 add_domain 时发生校验或值错误: {error}")
        return _build_add_domain_response(
            success=False,
            result=request.data,
            message=[str(error)],
        )
    except requests.RequestException as error:
        _log_exception("add-domain", f"处理 add_domain 时发生请求异常: {error}")
        return _build_add_domain_response(
            success=False,
            result=request.data,
            message=[str(error)],
        )


#############################################################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请提供 JSON 文件路径")
        sys.exit(1)

    input_json = sys.argv[1]
    with open(input_json, "r", encoding="utf-8") as file:
        input_data = json.load(file)

    result = add_domain(input_data)
    print("\n******* Add Domain Result *******")
    print(result.model_dump_json(indent=2, ensure_ascii=False))
