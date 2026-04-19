import json
import logging
import os
import requests
import urllib3
import sys
from typing import List, Dict, Any, Optional, Literal, Union, Tuple, Annotated
from pydantic import BaseModel, Field, ValidationError, ConfigDict, model_validator
from urllib.parse import quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)

#############################################################
### 日志配置 ###

LOG_LEVEL = os.getenv("AUTOZDNS_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("autozdns.modify_pool")


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
    name: str = Field(..., description="服务成员名称")
    weight: int = Field(..., description="权重")


class HealthCheckConfig(BaseModel):
    type: str = Field(..., description="健康检查类型,如:tcp,http")
    port: Optional[int] = Field(default=None, description="健康检查端口")


class DataBase(BaseModel):
    name: str = Field(..., description="地址池名称")
    records: List[RecordInfo] = Field(
        default_factory=list, description="地址池成员列表"
    )
    first_algorithm: Optional[str] = Field(default=None, description="一级调度算法")
    second_algorithm: Optional[str] = Field(default=None, description="二级调度算法")
    health_check: Optional[HealthCheckConfig] = Field(
        default=None, description="健康检查配置"
    )
    enable: bool = Field(default=False, description="是否启用地址池")


class ModifyPoolRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["modify_pool", "modified_pool"] = Field(
        ..., description="操作类型"
    )
    data: DataBase = Field(..., description="要修改的地址池列表")


#############################################################
### 标准输出规范 ###


class ModifyPoolResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: Optional[DataBase] = Field(default=None, description="")
    message: List[str] = Field(default_factory=list, description="操作结果消息")


#############################################################
### API: 查询地址池 ###


class GpoolParamsBase(BaseModel):
    host: str = Field(..., description="设备管理IP")
    pool: List[str] = Field(..., description="地址池名称")
    version: str = Field(default="2", description="API版本")

    """
    应该拼接成一下格式的查询字符串:
    search_attrs[0][0]=name&search_attrs[0][1]=eq&search_attrs[0][2]=wzw_test_pool&search_attrs[0][3]=or&search_attrs[1][0]=name&search_attrs[1][1]=eq&search_attrs[1][2]=wzw_pool&search_attrs[1][3]=and&version=2
    """


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
    pool_names = payload.get("pool", [])
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
        pool=pool_names,
    )

    response = requests.get(
        request_url,
        headers=headers,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("get_gpool", response)
    return response


"""
返回结果
{"resources":[{"id":"wzw_pool","name":"wzw_pool","alias_name":"wzw_pool","type":"A","enable":"yes","max_addr_ret":"1","ttl":"3600","first_algorithm":"wrr","first_algorithm_conf":{},"second_algorithm":"none","second_algorithm_conf":{},"fallback_ip":"","fallback_ipv6":"","pass":"1","hms":["tcp"],"hm_gm_flag":"yes","hm_gool_flag":"no","active_num_start":"","active_num_end":"","warning":"yes","gmember_list":[{"ratio":"1","enable":"yes","record":"wzw-1/10.10.10.10:443","seq":"1","real_id":15067,"name":"FT*wzw-1","id":"FT*wzw-1","dc_name":"FT","gmember_name":"wzw-1","ip":"10.10.10.10","port":"443"}],"daemon_id":"5014","real_id":5025,"first_sp_name":"","second_sp_name":"","auto_disabled":"no","key_1":"123","member_status":{"Unknown":1},"status":"GREEN","active_num_status":"BLUE","status_update_time":1776264785,"last_status":"RED"},{"id":"wzw_test_pool","name":"wzw_test_pool","alias_name":"wzw_test_pool","type":"A","enable":"no","max_addr_ret":"1","ttl":"30","first_algorithm":"wrr","first_algorithm_conf":{},"second_algorithm":"none","second_algorithm_conf":{},"fallback_ip":"","fallback_ipv6":"","pass":"1","hms":["tcp"],"hm_gm_flag":"yes","hm_gool_flag":"no","active_num_start":"","active_num_end":"","warning":"yes","gmember_list":[{"ratio":"1","enable":"yes","record":"10.10.10.100_443/10.10.10.100:443","seq":"1","real_id":15072,"name":"HF*10.10.10.100_443","id":"HF*10.10.10.100_443","dc_name":"HF","gmember_name":"10.10.10.100_443","ip":"10.10.10.100","port":"443"},{"ratio":"2","enable":"yes","record":"10.10.10.101_443/10.10.10.101:443","seq":"2","real_id":15073,"name":"HF*10.10.10.101_443","id":"HF*10.10.10.101_443","dc_name":"HF","gmember_name":"10.10.10.101_443","ip":"10.10.10.101","port":"443"}],"daemon_id":"5016","real_id":5027,"first_sp_name":"","second_sp_name":"","auto_disabled":"no","key_1":"","member_status":{"Unavailable":2},"status":"BLACK","active_num_status":"BLUE","status_update_time":1776266512,"last_status":"GREEN"}],"page_num":"1","page_size":"30","total_size":"2","has_third_device":"no","display_attrs":{"id":"gpool_in_add","user":"admin","res_type":"gpool_in_add","display":"{\"display_version\":\"v1.0\",\"is_check_data\":true,\"schema\":{\"status\":{\"width\":0.1},\"name\":{\"width\":0.2544755586878668},\"ttl\":{\"width\":0.07},\"type\":{\"width\":0.07},\"hm_gm_flag\":{\"width\":0.1},\"hms\":{\"width\":0.1},\"warning\":{\"width\":0.15},\"hm_gool_flag\":{\"width\":0.1},\"active_num\":{\"width\":0.15},\"first_algorithm\":{\"width\":0.15},\"second_algorithm\":{\"width\":0.15},\"fallback_ip\":{\"width\":0.1},\"fallback_ipv6\":{\"width\":0.1},\"gmember_list\":{\"width\":0.15},\"auto_disabled\":{\"width\":0.1},\"enable\":{\"width\":0.1},\"key_1\":{\"width\":0.1}}}","attrs":[{"id":"key_1","type":"text","display_name":"备注","component_type":"single_line_text","option_values":""}],"private_attrs":{"id":"gpool_in_add","res_type":"gpool_in_add","module_type":"ADD","attrs":["key_1"]}}}
"""

#############################################################
### API: 修改地址池 ###


class PutGpoolRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="设备管理IP")
    ttl: int = Field(default=30, description="地址池TTL")
    max_addr_ret: int = Field(default=1, description="地址池最大返回记录数")
    hm_gm_flag: str = Field(default="yes", description="服务成员状态检测")
    hms: List[str] = Field(default_factory=list, description="健康检测列表")
    pass_: str = Field(default="1", alias="pass", description="无意义参数,仅用于占位")
    hm_gool_flag: str = Field(default="no", description="活跃地址数检测")
    warning: str = Field(default="yes", description="异常处理,yes:告警,no:告警+禁用")
    first_algorithm: str = Field(..., description="一级调度算法,如:wrr")
    second_algorithm: str = Field(..., description="二级调度算法,如:none")
    auto_disabled: str = Field(default="no", description="是否自动禁用地址池")
    enable: str = Field(default="no", description="是否启用地址池")
    key_1: str = Field(default="", alias="key_1", description="备注")
    ids: List[str] = Field(..., description="地址池ID列表")


def put_gpool(
    req: PutGpoolRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
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
        pool=payload.get("ids", []),
    )

    response = requests.put(
        url,
        headers=headers,
        json=payload,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("put_gpool", response)
    return response


#############################################################
### API: 修改地址池成员 ###


class PutGpoolGmemberRequest(BaseModel):
    host: str = Field(..., description="设备管理IP")
    pool: str = Field(..., description="地址池名称")
    dc_gmember_name: str = Field(default="", description="数据中心名称_gmember名称")
    ratio: int = Field(..., description="权重")
    enable: str = Field(default="yes", description="是否启用，默认为yes")
    dc_name: str = Field(..., description="数据中心名称")
    gmember_name: str = Field(..., description="gmember名称")
    ids: List[str] = Field(default_factory=list, description="地址池成员ID列表")

    @model_validator(mode="after")
    def fill_dc_gmember_name(self):
        if self.dc_gmember_name == "":
            self.dc_gmember_name = f"{self.dc_name}/{self.gmember_name}"
        return self

    @model_validator(mode="after")
    def fill_ids(self):
        if not self.ids:
            self.ids = [f"{self.dc_name}*{self.gmember_name}"]
        return self

    """
    example:
    {
    "dc_gmember_name": "DCA/SLB-A",
    "ratio": "3",
    "enable": "yes",
    "dc_name": "DCA",
    "gmember_name": "SLB-A",
    "ids": [
        "DCA*SLB-A"
    ]
}"""


def put_gpoolgmember(
    req: PutGpoolGmemberRequest,
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
        "put_gpoolgmember",
        "准备发送更新地址池成员请求",
        url=url,
        pool=payload.get("ids", []),
    )

    response = requests.put(
        url,
        headers=headers,
        json=payload,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("put_gpoolgmember", response)
    return response


#############################################################
### 修改地址池核心逻辑 ###


def _parse_gpool_response(response: requests.Response) -> List[Dict[str, Any]]:
    response_data = response.json()
    if not isinstance(response_data, dict):
        raise ValueError("地址池查询接口返回格式异常")

    resources = response_data.get("resources", [])
    if not isinstance(resources, list):
        raise ValueError("地址池查询接口缺少 resources 列表")

    return [resource for resource in resources if isinstance(resource, dict)]


def _build_hms(
    health_check: Optional[HealthCheckConfig], current_hms: Any
) -> List[str]:
    if health_check is None:
        if isinstance(current_hms, list):
            return [str(item) for item in current_hms if str(item) != ""]
        return []

    if health_check.port is None:
        return [health_check.type]

    return [f"{health_check.type}"]


def _build_health_check_from_hms(hms: Any) -> Optional[HealthCheckConfig]:
    if not isinstance(hms, list) or not hms:
        return None

    first_item = str(hms[0])
    if first_item == "":
        return None

    if "_" not in first_item:
        return HealthCheckConfig(type=first_item)

    check_type, port_text = first_item.split("_", 1)
    try:
        return HealthCheckConfig(type=check_type, port=int(port_text))
    except ValueError:
        return HealthCheckConfig(type=check_type)


def _build_result_data(request_data: DataBase, resource: Dict[str, Any]) -> DataBase:
    current_members = resource.get("gmember_list", [])
    records = request_data.records
    if not records and isinstance(current_members, list):
        records = [
            RecordInfo(
                name=str(member.get("gmember_name", "")),
                weight=int(member.get("ratio", 1)),
            )
            for member in current_members
            if isinstance(member, dict) and str(member.get("gmember_name", "")) != ""
        ]

    return DataBase(
        name=request_data.name,
        records=records,
        first_algorithm=(
            request_data.first_algorithm
            if request_data.first_algorithm is not None
            else str(resource.get("first_algorithm", "wrr"))
        ),
        second_algorithm=(
            request_data.second_algorithm
            if request_data.second_algorithm is not None
            else str(resource.get("second_algorithm", "none"))
        ),
        health_check=(
            request_data.health_check
            if request_data.health_check is not None
            else _build_health_check_from_hms(resource.get("hms", []))
        ),
        enable=str(resource.get("enable", "no")).lower() == "yes",
    )


def _build_put_gpool_request(
    host: str,
    resource: Dict[str, Any],
    request_data: DataBase,
) -> PutGpoolRequest:
    payload = {
        "host": host,
        "ttl": int(resource.get("ttl", 30)),
        "max_addr_ret": int(resource.get("max_addr_ret", 1)),
        "hm_gm_flag": str(resource.get("hm_gm_flag", "yes")),
        "hms": _build_hms(request_data.health_check, resource.get("hms", [])),
        "pass": "1",
        "hm_gool_flag": str(resource.get("hm_gool_flag", "no")),
        "warning": str(resource.get("warning", "yes")),
        "first_algorithm": (
            request_data.first_algorithm
            if request_data.first_algorithm is not None
            else str(resource.get("first_algorithm", "wrr"))
        ),
        "second_algorithm": (
            request_data.second_algorithm
            if request_data.second_algorithm is not None
            else str(resource.get("second_algorithm", "none"))
        ),
        "auto_disabled": str(resource.get("auto_disabled", "no")),
        "enable": str(resource.get("enable", "no")),
        "key_1": str(resource.get("key_1", "")),
        "ids": [str(resource.get("id", resource.get("name", "")))],
    }
    return PutGpoolRequest.model_validate(payload)


def _build_put_gpoolgmember_request(
    host: str,
    pool_name: str,
    member: Dict[str, Any],
    ratio: int,
) -> PutGpoolGmemberRequest:
    dc_name = str(member.get("dc_name", ""))
    gmember_name = str(member.get("gmember_name", ""))
    if dc_name == "" or gmember_name == "":
        raise ValueError("地址池成员缺少 dc_name 或 gmember_name，无法构造更新请求")

    return PutGpoolGmemberRequest(
        host=host,
        pool=pool_name,
        ratio=ratio,
        enable=str(member.get("enable", "yes")),
        dc_name=dc_name,
        gmember_name=gmember_name,
    )


def _build_member_ratio_mapping(records: List[RecordInfo]) -> Dict[str, int]:
    return {record.name: record.weight for record in records}


def modify_pool(data: Dict[str, Any]) -> ModifyPoolResponse:
    """
    修改地址池核心逻辑
    1. 将输入数据转换为 ModifyPoolRequest 对象
    2. 调用 get_gpool 查询当前地址池信息，判断地址池是否存在
    3. 如果地址池存在，调用 put_gpool 更新地址池属性,接口的修改方式为覆盖,但要求逻辑为空则不修改,所以不修改的部分需要预先查询地址池信息并保留原有值
    4. 涉及records地址池成员修改的调用 put_gpoolgmember 接口更新地址池成员信息,接口的修改方式为覆盖,但要求逻辑为空则不修改,所以不修改的部分需要预先查询地址池成员信息并保留原有值
    5. 根据接口调用结果构造 ModifyPoolResponse 对象并返回

    """

    try:
        request = ModifyPoolRequest.model_validate(data)
    except ValidationError as error:
        _log_exception("modify_pool", "ModifyPoolRequest 数据验证失败")
        return ModifyPoolResponse(success=False, message=[str(error)])

    auth = (request.device_info.username, request.device_info.password)
    result = DataBase(name=request.data.name)
    gpool_query = GpoolParamsBase(
        host=request.device_info.management_ip,
        pool=[request.data.name],
    )

    _log_step(
        "modify_pool",
        "开始修改地址池",
        pool_name=request.data.name,
        management_ip=request.device_info.management_ip,
    )

    try:
        query_response = get_gpool(gpool_query, verify_ssl=False, auth=auth)
    except requests.RequestException as error:
        _log_exception("modify_pool", "调用 get_gpool 失败")
        return ModifyPoolResponse(
            success=False,
            result=result,
            message=[f"查询地址池请求异常: {error}"],
        )

    if not query_response.ok:
        return ModifyPoolResponse(
            success=False,
            result=result,
            message=[
                f"查询地址池失败, status={query_response.status_code}, body={query_response.text[:200]}"
            ],
        )

    try:
        resources = _parse_gpool_response(query_response)
    except (ValueError, json.JSONDecodeError) as error:
        _log_exception("modify_pool", "解析 get_gpool 返回失败")
        return ModifyPoolResponse(
            success=False,
            result=result,
            message=[f"解析地址池查询结果失败: {error}"],
        )

    target_resource = next(
        (
            resource
            for resource in resources
            if str(resource.get("name", "")) == request.data.name
        ),
        None,
    )
    if target_resource is None:
        return ModifyPoolResponse(
            success=False,
            result=result,
            message=[f"未找到地址池 {request.data.name}"],
        )

    result = _build_result_data(request.data, target_resource)

    put_request = _build_put_gpool_request(
        request.device_info.management_ip,
        target_resource,
        request.data,
    )

    try:
        put_response = put_gpool(put_request, verify_ssl=False, auth=auth)
    except requests.RequestException as error:
        _log_exception("modify_pool", "调用 put_gpool 失败")
        return ModifyPoolResponse(
            success=False,
            result=result,
            message=[f"修改地址池属性请求异常: {error}"],
        )

    if not put_response.ok:
        return ModifyPoolResponse(
            success=False,
            result=result,
            message=[
                f"修改地址池属性失败, status={put_response.status_code}, body={put_response.text[:200]}"
            ],
        )

    messages = [f"地址池 {request.data.name} 属性修改成功"]
    member_ratio_mapping = _build_member_ratio_mapping(request.data.records)
    pool_members = target_resource.get("gmember_list", [])
    if not isinstance(pool_members, list):
        pool_members = []

    if request.data.records:
        current_members = {
            str(member.get("gmember_name", "")): member
            for member in pool_members
            if isinstance(member, dict) and str(member.get("gmember_name", "")) != ""
        }

        missing_members = [
            record.name
            for record in request.data.records
            if record.name not in current_members
        ]
        if missing_members:
            return ModifyPoolResponse(
                success=False,
                result=result,
                message=messages
                + [f"以下服务成员不在地址池中，无法修改: {', '.join(missing_members)}"],
            )

        for member_name, member in current_members.items():
            ratio = member_ratio_mapping.get(member_name, int(member.get("ratio", 1)))
            try:
                member_request = _build_put_gpoolgmember_request(
                    request.device_info.management_ip,
                    request.data.name,
                    member,
                    ratio,
                )
            except ValueError as error:
                return ModifyPoolResponse(
                    success=False,
                    result=result,
                    message=messages + [str(error)],
                )

            try:
                member_response = put_gpoolgmember(
                    member_request,
                    verify_ssl=False,
                    auth=auth,
                )
            except requests.RequestException as error:
                _log_exception("modify_pool", "调用 put_gpoolgmember 失败")
                return ModifyPoolResponse(
                    success=False,
                    result=result,
                    message=messages + [f"修改成员 {member_name} 请求异常: {error}"],
                )

            if not member_response.ok:
                return ModifyPoolResponse(
                    success=False,
                    result=result,
                    message=messages
                    + [
                        f"修改成员 {member_name} 失败, status={member_response.status_code}, body={member_response.text[:200]}"
                    ],
                )

        messages.append(f"地址池 {request.data.name} 成员权重修改成功")

    return ModifyPoolResponse(success=True, result=result, message=messages)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请提供 JSON 文件路径")
        sys.exit(1)

    input_json = sys.argv[1]
    with open(input_json, "r", encoding="utf-8") as file:
        input_data = json.load(file)

    result = modify_pool(input_data)
    print("\n******* Modify Pool Result *******")
    print(result.model_dump_json(indent=2, ensure_ascii=False))
