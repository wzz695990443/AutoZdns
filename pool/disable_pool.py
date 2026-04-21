import json
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
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
    name: str = Field(..., description="地址池名称")
    enable: bool = Field(default=False, description="是否启用地址池")


class DisablePoolRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["disable_pool", "disabled_pool"] = Field(
        ..., description="操作类型"
    )
    data: DataBase = Field(..., description="要禁用的地址池列表")


#############################################################
### 标准输出规范 ###


class DisablePoolResponse(BaseModel):
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
### 禁用地址池核心逻辑 ###


def _parse_gpool_response(response: requests.Response) -> List[Dict[str, Any]]:
    response_data = response.json()
    if not isinstance(response_data, dict):
        raise ValueError("地址池查询接口返回格式异常")

    resources = response_data.get("resources", [])
    if not isinstance(resources, list):
        raise ValueError("地址池查询接口缺少 resources 列表")

    return [resource for resource in resources if isinstance(resource, dict)]


def _build_put_gpool_request(host: str, resource: Dict[str, Any]) -> PutGpoolRequest:
    payload = {
        "host": host,
        "ttl": int(resource.get("ttl", 30)),
        "max_addr_ret": int(resource.get("max_addr_ret", 1)),
        "hm_gm_flag": str(resource.get("hm_gm_flag", "yes")),
        "hms": [str(item) for item in resource.get("hms", []) if str(item) != ""],
        "pass": str(resource.get("pass", "1")),
        "hm_gool_flag": str(resource.get("hm_gool_flag", "no")),
        "warning": str(resource.get("warning", "yes")),
        "first_algorithm": str(resource.get("first_algorithm", "wrr")),
        "second_algorithm": str(resource.get("second_algorithm", "none")),
        "auto_disabled": str(resource.get("auto_disabled", "no")),
        "enable": "no",
        "key_1": str(resource.get("key_1", "")),
        "ids": [str(resource.get("id", resource.get("name", "")))],
    }
    return PutGpoolRequest.model_validate(payload)


def disable_pools(data: Dict[str, Any]) -> DisablePoolResponse:
    """禁用地址池的核心逻辑
    1.通过标准输入规范校验输入数据
    2.调用API查询地址池信息,获取地址池ID以及修改地址池所需的全部信息
    3.调用API修改地址池,将地址池禁用
    4.通过标准输出规范返回操作结果
    """

    try:
        request = DisablePoolRequest.model_validate(data)
    except ValidationError as error:
        _log_exception("disable_pools", "DisablePoolRequest 数据验证失败")
        return DisablePoolResponse(success=False, message=[str(error)])

    auth = (request.device_info.username, request.device_info.password)
    result = DataBase(name=request.data.name, enable=False)
    gpool_query = GpoolParamsBase(
        host=request.device_info.management_ip,
        pool=[request.data.name],
    )

    _log_step(
        "disable_pools",
        "开始禁用地址池",
        pool_name=request.data.name,
        management_ip=request.device_info.management_ip,
    )

    try:
        query_response = get_gpool(gpool_query, verify_ssl=False, auth=auth)
    except requests.RequestException as error:
        _log_exception("disable_pools", "调用 get_gpool 失败")
        return DisablePoolResponse(
            success=False,
            result=result,
            message=[f"查询地址池请求异常: {error}"],
        )

    if not query_response.ok:
        return DisablePoolResponse(
            success=False,
            result=result,
            message=[
                f"查询地址池失败, status={query_response.status_code}, body={query_response.text[:200]}"
            ],
        )

    try:
        resources = _parse_gpool_response(query_response)
    except (ValueError, json.JSONDecodeError) as error:
        _log_exception("disable_pools", "解析 get_gpool 返回失败")
        return DisablePoolResponse(
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
        return DisablePoolResponse(
            success=False,
            result=result,
            message=[f"未找到地址池 {request.data.name}"],
        )

    if str(target_resource.get("enable", "")).lower() == "no":
        return DisablePoolResponse(
            success=True,
            result=result,
            message=[f"地址池 {request.data.name} 已经是禁用状态"],
        )

    put_request = _build_put_gpool_request(
        request.device_info.management_ip,
        target_resource,
    )

    try:
        put_response = put_gpool(put_request, verify_ssl=False, auth=auth)
    except requests.RequestException as error:
        _log_exception("disable_pools", "调用 put_gpool 失败")
        return DisablePoolResponse(
            success=False,
            result=result,
            message=[f"禁用地址池请求异常: {error}"],
        )

    if not put_response.ok:
        return DisablePoolResponse(
            success=False,
            result=result,
            message=[
                f"禁用地址池失败, status={put_response.status_code}, body={put_response.text[:200]}"
            ],
        )

    return DisablePoolResponse(
        success=True,
        result=result,
        message=[f"地址池 {request.data.name} 禁用成功"],
    )


def main() -> int:
    input_path = (
        sys.argv[1] if len(sys.argv) > 1 else _default_input_path("disable_pool.json")
    )
    _log_step("main", "脚本启动", input_path=input_path, log_file=LOG_FILE)

    try:
        input_data = _load_input_data(input_path)
    except (OSError, json.JSONDecodeError) as exc:
        _log_exception("main", f"读取输入文件失败: {input_path}")
        _print_cli_error(f"读取输入文件失败: {exc}")
        return 1

    result = disable_pools(input_data)
    _log_step("main", "脚本执行完成", success=result.success)
    _print_cli_result(result)
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
