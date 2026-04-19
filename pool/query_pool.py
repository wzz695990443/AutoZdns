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
logger = logging.getLogger("autozdns.query_pool")


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


class ConditionBase(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    field_name: str = Field(..., alias="filed", description="查询字段")
    value: str = Field(..., description="查询值")
    match_type: str = Field(default="fuzzy", description="匹配类型，fuzzy 或 exact")

    @model_validator(mode="before")
    @classmethod
    def fill_field_alias(cls, data: Any) -> Any:
        if isinstance(data, dict) and "filed" not in data and "field" in data:
            data = dict(data)
            data["filed"] = data["field"]
        return data

    @model_validator(mode="after")
    def normalize_match_type(self) -> "ConditionBase":
        match_type = self.match_type.lower()
        if match_type not in {"fuzzy", "exact"}:
            raise ValueError("match_type 仅支持 fuzzy 或 exact")
        self.match_type = match_type
        return self


class OrderBase(BaseModel):
    order_key: str = Field(..., description="排序字段")
    order_type: str = Field(..., description="排序方向，ASC 或 DESC")

    @model_validator(mode="after")
    def normalize_order_type(self) -> "OrderBase":
        order_type = self.order_type.upper()
        if order_type not in {"ASC", "DESC"}:
            raise ValueError("order_type 仅支持 ASC 或 DESC")
        self.order_type = order_type
        return self


class QueryPoolRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["query_pool"] = Field(..., description="操作类型")
    conditions: List[ConditionBase] = Field(..., description="查询条件列表")
    orders: Optional[OrderBase] = Field(default=None, description="排序规则")

    @model_validator(mode="after")
    def validate_conditions_not_empty(self) -> "QueryPoolRequest":
        if not self.conditions:
            raise ValueError("conditions 至少需要提供一个查询条件")
        return self


#############################################################
### 标准输出规范 ###
class RecordInfo(BaseModel):
    name: str = Field(..., description="服务成员名称")
    value: Optional[str] = Field(default=None, description="服务成员值，格式为IP或域名")
    enabled: Optional[bool] = Field(default=None, description="服务成员是否启用")
    weight: int = Field(..., description="权重")


class HealthCheckConfig(BaseModel):
    type: str = Field(..., description="健康检查类型,如:tcp,http")
    port: Optional[int] = Field(default=None, description="健康检查端口")


class OutBase(BaseModel):
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


class QueryPoolResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: List[OutBase] = Field(default_factory=list, description="查询结果列表")
    message: List[str] = Field(default_factory=list, description="操作结果消息")


#############################################################
### API: 查询地址池 ###


class GpoolParamsBase(BaseModel):
    host: str = Field(..., description="设备管理IP")
    conditions: List[ConditionBase] = Field(..., description="查询条件列表")
    orders: Optional[OrderBase] = Field(default=None, description="排序规则")
    version: str = Field(default="2", description="API版本")

    """
    应该拼接成一下格式的查询字符串:
    search_attrs[0][0]=name&search_attrs[0][1]=eq&search_attrs[0][2]=wzw_test_pool&search_attrs[0][3]=or&search_attrs[1][0]=name&search_attrs[1][1]=eq&search_attrs[1][2]=wzw_pool&search_attrs[1][3]=and&version=2
    """


def _build_gpool_query(
    conditions: List[ConditionBase],
    orders: Optional[OrderBase] = None,
    version: str = "2",
) -> str:
    query_parts: List[str] = []
    operator_mapping = {
        "fuzzy": "eq",
        "exact": "in",
    }

    for index, condition in enumerate(conditions):
        connector = "and"
        query_parts.extend(
            [
                f"search_attrs[{index}][0]={quote(str(condition.field_name), safe='')}",
                f"search_attrs[{index}][1]={operator_mapping[condition.match_type]}",
                f"search_attrs[{index}][2]={quote(str(condition.value), safe='')}",
                f"search_attrs[{index}][3]={connector}",
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


def get_gpool(
    req: GpoolParamsBase,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    payload = req.model_dump(by_alias=True, exclude_none=True)
    host_value = payload.pop("host", None)
    conditions = req.conditions
    orders = req.orders
    version_value = payload.get("version", "2")

    url = f"https://{host_value}:20120/gpool"
    query_string = _build_gpool_query(conditions, orders, version_value)
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
        conditions=[item.model_dump(by_alias=True) for item in conditions],
        orders=orders.model_dump() if orders is not None else None,
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
### 查询地址池核心逻辑 ###


def _parse_gpool_response(response: requests.Response) -> List[Dict[str, Any]]:
    response_data = response.json()
    if not isinstance(response_data, dict):
        raise ValueError("地址池查询接口返回格式异常")

    resources = response_data.get("resources", [])
    if not isinstance(resources, list):
        raise ValueError("地址池查询接口缺少 resources 列表")

    return [resource for resource in resources if isinstance(resource, dict)]


def _get_member_port(members: Any) -> Optional[int]:
    if not isinstance(members, list):
        return None

    for member in members:
        if not isinstance(member, dict):
            continue

        port_text = str(member.get("port", "")).strip()
        if port_text == "":
            continue

        try:
            return int(port_text)
        except ValueError:
            continue

    return None


def _build_health_check_from_hms(
    hms: Any, members: Any = None
) -> Optional[HealthCheckConfig]:
    if not isinstance(hms, list) or not hms:
        return None

    first_item = str(hms[0])
    if first_item == "":
        return None

    member_port = _get_member_port(members)

    if "_" not in first_item:
        return HealthCheckConfig(type=first_item, port=member_port)

    check_type, port_text = first_item.split("_", 1)
    try:
        return HealthCheckConfig(type=check_type, port=int(port_text))
    except ValueError:
        return HealthCheckConfig(type=check_type, port=member_port)


def _build_out_base(resource: Dict[str, Any]) -> OutBase:
    members = resource.get("gmember_list", [])
    records: List[RecordInfo] = []

    if isinstance(members, list):
        for member in members:
            if not isinstance(member, dict):
                continue

            member_name = str(member.get("gmember_name", ""))
            if member_name == "":
                continue

            try:
                weight = int(member.get("ratio", 1))
            except (TypeError, ValueError):
                weight = 1

            member_ip = str(member.get("ip", "")).strip()
            member_port = str(member.get("port", "")).strip()
            member_value: Optional[str] = None
            if member_ip and member_port:
                member_value = f"{member_ip}:{member_port}"
            elif member_ip:
                member_value = member_ip
            elif member_port:
                member_value = member_port

            member_enable = str(member.get("enable", "")).lower()
            member_enabled: Optional[bool] = None
            if member_enable in {"yes", "no"}:
                member_enabled = member_enable == "yes"

            records.append(
                RecordInfo(
                    name=member_name,
                    value=member_value,
                    enabled=member_enabled,
                    weight=weight,
                )
            )

    return OutBase(
        name=str(resource.get("name", "")),
        records=records,
        first_algorithm=(
            str(resource.get("first_algorithm"))
            if resource.get("first_algorithm") not in (None, "")
            else None
        ),
        second_algorithm=(
            str(resource.get("second_algorithm"))
            if resource.get("second_algorithm") not in (None, "")
            else None
        ),
        health_check=_build_health_check_from_hms(resource.get("hms", []), members),
        enable=str(resource.get("enable", "no")).lower() == "yes",
    )


def _matches_condition(resource: Dict[str, Any], condition: ConditionBase) -> bool:
    actual_value = str(resource.get(condition.field_name, ""))
    expected_value = str(condition.value)

    if condition.match_type == "exact":
        return actual_value == expected_value

    return expected_value in actual_value


def _filter_resources(
    resources: List[Dict[str, Any]], conditions: List[ConditionBase]
) -> List[Dict[str, Any]]:
    return [
        resource
        for resource in resources
        if all(_matches_condition(resource, condition) for condition in conditions)
    ]


def _sort_resources(
    resources: List[Dict[str, Any]], orders: Optional[OrderBase]
) -> List[Dict[str, Any]]:
    if orders is None:
        return resources

    reverse = orders.order_type == "DESC"
    order_key = orders.order_key
    return sorted(
        resources, key=lambda item: str(item.get(order_key, "")), reverse=reverse
    )


def query_pool(data: Dict[str, Any]) -> QueryPoolResponse:
    """
    查询地址池核心逻辑
    1. 解析输入数据，构建请求对象
    2. 调用API查询地址池信息
    3. 解析API响应，构建输出对象
    4. 返回输出对象
    """
    try:
        request_data = QueryPoolRequest.model_validate(data)
        _log_step(
            "query_pool",
            "输入参数校验通过",
            conditions=[
                item.model_dump(by_alias=True) for item in request_data.conditions
            ],
            orders=request_data.orders.model_dump() if request_data.orders else None,
        )
    except ValidationError as exc:
        _log_exception("query_pool", "输入参数校验失败")
        return QueryPoolResponse(
            success=False,
            message=[f"输入参数校验失败: {exc}"],
        )

    request_payload = GpoolParamsBase(
        host=request_data.device_info.management_ip,
        conditions=request_data.conditions,
        orders=request_data.orders,
    )

    try:
        response = get_gpool(
            request_payload,
            auth=(
                request_data.device_info.username,
                request_data.device_info.password,
            ),
        )
    except requests.RequestException as exc:
        _log_exception("query_pool", "查询地址池请求失败")
        return QueryPoolResponse(
            success=False,
            message=[f"查询地址池请求失败: {exc}"],
        )

    if not response.ok:
        return QueryPoolResponse(
            success=False,
            message=[
                f"查询地址池失败，HTTP状态码: {response.status_code}",
                response.text,
            ],
        )

    try:
        resources = _parse_gpool_response(response)
        resources = _filter_resources(resources, request_data.conditions)
        resources = _sort_resources(resources, request_data.orders)
        result = [_build_out_base(resource) for resource in resources]
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        _log_exception("query_pool", "解析地址池查询结果失败")
        return QueryPoolResponse(
            success=False,
            message=[f"解析地址池查询结果失败: {exc}"],
        )

    return QueryPoolResponse(
        success=True,
        result=result,
        message=[f"查询成功，共匹配到 {len(result)} 个地址池"],
    )


if __name__ == "__main__":
    input_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(os.path.dirname(__file__), "input", "query_pool.json")
    )

    with open(input_path, "r", encoding="utf-8") as file:
        input_data = json.load(file)

    response = query_pool(input_data)
    print("\n******* Modify Pool Result *******")
    print(json.dumps(response.model_dump(), ensure_ascii=False, indent=4))
    