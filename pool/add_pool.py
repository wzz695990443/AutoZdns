import json
import logging
import os
import requests
import urllib3
import sys
from typing import List, Dict, Any, Optional, Literal, Union, Tuple, Annotated
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
logger = logging.getLogger("autozdns.add_pool")


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


class RecordInfo(BaseModel):
    name: str = Field(..., description="IP地址+端口,例如1.1.1.1_443")
    weight: int = Field(..., description="权重")


class HealthCheckConfig(BaseModel):
    type: str = Field(..., description="健康检查类型,如:tcp,http")
    port: Optional[int] = Field(None, description="健康检查端口")


class DataBase(BaseModel):
    name: str = Field(..., description="IP地址+端口,例如1.1.1.1_443")
    type: str = Field(..., description="记录类型,如:A,AAAA")
    records: List[RecordInfo] = Field(..., description="记录列表")
    health_check: HealthCheckConfig = Field(..., description="健康检查配置")
    first_algorithm: str = Field(..., description="一级调度算法,如:wrr")
    second_algorithm: str = Field(..., description="二级调度算法,如:none")


class AddRecordRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["add_pool", "create_pool"] = Field(..., description="操作类型")
    data: DataBase = Field(..., description="要添加的记录列表")


#############################################################
### 标准输出规范 ###


class AddPoolResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    data: Optional[DataBase] = Field(default=None, description="要添加的记录列表")
    message: List[str] = Field(default_factory=list, description="操作结果消息")


#############################################################
### API: 新增地址池 ###


class GpoolRequestBase(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="设备管理IP")
    name: str = Field(..., description="地址池名称")
    ttl: int = Field(default=30, description="地址池TTL")
    type: str = Field(..., description="地址池类型,如:A,AAAA")
    max_addr_ret: int = Field(default=1, description="地址池最大返回记录数")
    hm_gm_flag: str = Field(default="yes", description="服务成员状态检测")
    hms: List[str] = Field(default_factory=list, description="健康检测列表")
    pass_: str = Field(default="1", alias="pass", description="无意义参数,仅用于占位")
    hm_gool_flag: str = Field(default="no", description="活跃地址数检测")
    warning: str = Field(default="yes", description="异常处理,yes:告警,no:告警+禁用")
    first_algorithm: str = Field(..., description="一级调度算法,如:wrr")
    second_algorithm: str = Field(..., description="二级调度算法,如:none")
    auto_disabled: str = Field(default="no", description="成员异常自动禁用")
    enable: str = Field(default="yes", description="是否启用")
    key_1: str = Field(default="", alias="key_1", description="备注")


def post_gpool(
    req: GpoolRequestBase,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    """
    新增地址池
    """
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
        "post_gpool",
        "准备发送新增Gpool请求",
        url=url,
    )
    response = requests.post(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("post_gpool", response)
    return response


#############################################################
### API: 查询服务成员 ###


def get_gmember(
    host: str,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    url = f"https://{host}:20120/dc/gmember"
    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{host}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }
    _log_step(
        "get_gmember",
        "准备发送查询Gmember服务成员请求",
        url=url,
    )
    response = requests.get(url, headers=headers, verify=verify_ssl, auth=auth)
    _log_http_response("get_gmember", response)
    return response


"""
请求结果格式为:
{
    "YZ": [
        {
            "dc_name": "YZ",
            "gmember_name": "server_2.0.3.9",
            "ip": "2.0.3.9",
            "port": "8088"
        },
        {
            "dc_name": "YZ",
            "gmember_name": "server_2.0.3.253",
            "ip": "2.0.3.253",
            "port": "8088"
        },
        {
            "dc_name": "YZ",
            "gmember_name": "server_2.0.3.254",
            "ip": "2.0.3.254",
            "port": "8088"
        },
    ],
    "FT": [
        {
            "dc_name": "FT",
            "gmember_name": "server_1.0.0.25",
            "ip": "1.0.0.25",
            "port": "8088"
        },
        {
            "dc_name": "FT",
            "gmember_name": "server_1.0.0.26",
            "ip": "1.0.0.26",
            "port": "8088"
        },
        {
            "dc_name": "FT",
            "gmember_name": "server_1.0.0.27",
            "ip": "1.0.0.27",
            "port": "8088"
        },
    ],
    "HF": [
        {
            "dc_name": "HF",
            "gmember_name": "server_3.0.0.11",
            "ip": "3.0.0.11",
            "port": "8088"
        },
        {
            "dc_name": "HF",
            "gmember_name": "server_3.0.0.12",
            "ip": "3.0.0.12",
            "port": "8088"
        },
        {
            "dc_name": "HF",
            "gmember_name": "server_3.0.0.13",
            "ip": "3.0.0.13",
            "port": "8088"
        },
    ]
}

"""

#############################################################
### API: 新增地址池服务成员记录 ###


class GpoolGmemberRequestBase(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="设备管理IP")
    pool: str = Field(..., description="地址池名称")
    dc_name: str = Field(..., alias="dc_name", description="数据中心名称")
    member_name: str = Field(..., alias="gmember_name", description="服务成员名称")
    ratio: int = Field(..., alias="ratio", description="服务成员权重")
    enable: str = Field(default="yes", alias="enable", description="是否启用")


def post_gpoolgmember(
    req: GpoolGmemberRequestBase,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)
    pool_value = payload.pop("pool", None)

    url = f"https://{host_value}:20120/gpool/{pool_value}/gpoolgmember"

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
        "post_gpoolgmember",
        "准备发送新增gpoolgmember请求",
        url=url,
    )
    response = requests.post(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("post_gpoolgmember", response)
    return response


#############################################################
### 新增地址池核心逻辑 ###


def _build_hms(health_check: HealthCheckConfig) -> List[str]:
    if health_check.port is None:
        return [health_check.type]

    return [f"{health_check.type}"]


def _build_gpool_request(request: AddRecordRequest) -> GpoolRequestBase:
    return GpoolRequestBase(
        host=request.device_info.management_ip,
        name=request.data.name,
        type=request.data.type,
        hms=_build_hms(request.data.health_check),
        first_algorithm=request.data.first_algorithm,
        second_algorithm=request.data.second_algorithm,
    )


def _parse_gmember_response(response: requests.Response) -> Dict[str, Dict[str, Any]]:
    response_data = response.json()
    if not isinstance(response_data, dict):
        raise ValueError("Gmember 查询接口返回格式异常")

    gmember_index: Dict[str, Dict[str, Any]] = {}
    for dc_name, members in response_data.items():
        if not isinstance(members, list):
            continue

        for member in members:
            if not isinstance(member, dict):
                continue

            member_name = str(member.get("gmember_name", ""))
            if member_name == "":
                continue

            normalized_member = dict(member)
            normalized_member.setdefault("dc_name", dc_name)
            gmember_index[member_name] = normalized_member

    return gmember_index


def _build_gpool_gmember_request(
    host: str,
    pool_name: str,
    record: RecordInfo,
    gmember_info: Dict[str, Any],
) -> GpoolGmemberRequestBase:
    return GpoolGmemberRequestBase(
        host=host,
        pool=pool_name,
        dc_name=str(gmember_info.get("dc_name", "")),
        gmember_name=str(gmember_info.get("gmember_name", record.name)),
        ratio=record.weight,
    )


def add_pool(data: Dict[str, Any]) -> AddPoolResponse:
    """
    逻辑:
    1.通过AddRecordRequest校验输入数据
    2.构建GpoolRequestBase请求体
    3.调用post_gpool接口新增地址池
    4.调用get_gmember接口查询现有服务成员列表,根据IP和端口过滤出目标服务成员,获取其数据中心名称和服务成员名称
    5.构建GpoolGmemberRequestBase请求体,调用post_gpoolgmember接口新增地址池服务成员记录

    """

    try:
        request = AddRecordRequest.model_validate(data)
    except ValidationError as error:
        _log_exception("add_pool", "AddRecordRequest 数据验证失败")
        return AddPoolResponse(success=False, message=[str(error)])

    auth = (request.device_info.username, request.device_info.password)
    messages: List[str] = []
    success = True

    gpool_request = _build_gpool_request(request)
    _log_step(
        "add_pool",
        "开始新增地址池",
        pool_name=gpool_request.name,
        record_count=len(request.data.records),
        management_ip=request.device_info.management_ip,
    )

    try:
        gpool_response = post_gpool(gpool_request, verify_ssl=False, auth=auth)
    except requests.RequestException as error:
        _log_exception("add_pool", "调用 post_gpool 失败")
        return AddPoolResponse(
            success=False,
            data=request.data,
            message=[f"地址池创建请求异常: {error}"],
        )

    if not gpool_response.ok:
        return AddPoolResponse(
            success=False,
            data=request.data,
            message=[
                f"地址池创建失败, status={gpool_response.status_code}, body={gpool_response.text[:200]}"
            ],
        )

    messages.append(f"地址池 {request.data.name} 创建成功")

    try:
        gmember_response = get_gmember(
            request.device_info.management_ip,
            verify_ssl=False,
            auth=auth,
        )
    except requests.RequestException as error:
        _log_exception("add_pool", "调用 get_gmember 失败")
        return AddPoolResponse(
            success=False,
            data=request.data,
            message=messages + [f"查询服务成员请求异常: {error}"],
        )

    if not gmember_response.ok:
        return AddPoolResponse(
            success=False,
            data=request.data,
            message=messages
            + [
                f"查询服务成员失败, status={gmember_response.status_code}, body={gmember_response.text[:200]}"
            ],
        )

    try:
        gmember_index = _parse_gmember_response(gmember_response)
    except (ValueError, json.JSONDecodeError) as error:
        _log_exception("add_pool", "解析 get_gmember 返回失败")
        return AddPoolResponse(
            success=False,
            data=request.data,
            message=messages + [f"解析服务成员返回失败: {error}"],
        )

    for record in request.data.records:
        gmember_info = gmember_index.get(record.name)
        if gmember_info is None:
            success = False
            messages.append(f"未找到服务成员 {record.name}, 无法加入地址池")
            continue

        gpool_gmember_request = _build_gpool_gmember_request(
            request.device_info.management_ip,
            request.data.name,
            record,
            gmember_info,
        )

        _log_step(
            "add_pool",
            "准备将服务成员加入地址池",
            pool=request.data.name,
            gmember_name=gpool_gmember_request.member_name,
            dc_name=gpool_gmember_request.dc_name,
            ratio=gpool_gmember_request.ratio,
        )

        try:
            member_response = post_gpoolgmember(
                gpool_gmember_request,
                verify_ssl=False,
                auth=auth,
            )
        except requests.RequestException as error:
            success = False
            _log_exception("add_pool", "调用 post_gpoolgmember 失败")
            messages.append(f"{record.name}: 加入地址池请求异常: {error}")
            continue

        if member_response.ok:
            messages.append(f"{record.name}: 加入地址池成功")
            continue

        success = False
        messages.append(
            f"{record.name}: 加入地址池失败, status={member_response.status_code}, body={member_response.text[:200]}"
        )

    return AddPoolResponse(success=success, data=request.data, message=messages)


#############################################################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请提供 JSON 文件路径")
        sys.exit(1)

    input_json = sys.argv[1]
    with open(input_json, "r", encoding="utf-8") as file:
        input_data = json.load(file)

    result = add_pool(input_data)
    print("\n******* Add Pool Result *******")
    print(result.model_dump_json(indent=2, ensure_ascii=False))
