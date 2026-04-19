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
logger = logging.getLogger("autozdns.delete_pool")


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
    name: str = Field(..., description="地址池名称")
    enable: bool = Field(default=False, description="是否启用地址池")


class DeletePoolRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["delete_pool"] = Field(..., description="操作类型")
    data: DataBase = Field(..., description="要删除的地址池列表")


#############################################################
### 标准输出规范 ###


class DeletePoolResponse(BaseModel):
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


#############################################################
### API: 删除地址池 ###


class DeleteGpoolRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="设备管理IP")
    ids: List[str] = Field(..., description="地址池ID列表")


def delete_gpool(
    req: DeleteGpoolRequest,
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
        "delete_gpool",
        "准备发送删除地址池请求",
        url=url,
        pool=payload.get("ids", []),
    )

    response = requests.delete(
        url,
        headers=headers,
        json=payload,
        verify=verify_ssl,
        auth=auth,
    )
    _log_http_response("delete_gpool", response)
    return response


#############################################################
### 删除地址池核心逻辑 ###


def _parse_gpool_response(response: requests.Response) -> List[Dict[str, Any]]:
    response_data = response.json()
    if not isinstance(response_data, dict):
        raise ValueError("地址池查询接口返回格式异常")

    resources = response_data.get("resources", [])
    if not isinstance(resources, list):
        raise ValueError("地址池查询接口缺少 resources 列表")

    return [resource for resource in resources if isinstance(resource, dict)]


def _build_delete_gpool_request(
    host: str, resource: Dict[str, Any]
) -> DeleteGpoolRequest:
    pool_id = str(resource.get("id", resource.get("name", "")))
    if pool_id == "":
        raise ValueError("地址池缺少可删除的 ID")

    return DeleteGpoolRequest(host=host, ids=[pool_id])


def delete_pool(data: Dict[str, Any]) -> DeletePoolResponse:
    """删除地址池核心逻辑
    1. 从标准输入读取请求数据并解析为 DeletePoolRequest 对象
    2. 查询要删除的地址池信息，获取地址池ID,获取地址池是否启用,以及gmember_list是否存在成员
    3. 如果地址池启用且存在成员,则返回失败结果,并在message中说明原因
    4. 如果地址池已被禁用,或者虽然启用但没有服务成员,则调用删除地址池API删除地址池,并根据API调用结果返回成功或失败结果,在message中说明删除结果
    """

    try:
        request = DeletePoolRequest.model_validate(data)
    except ValidationError as error:
        _log_exception("delete_pool", "DeletePoolRequest 数据验证失败")
        return DeletePoolResponse(success=False, message=[str(error)])

    auth = (request.device_info.username, request.device_info.password)
    result = DataBase(name=request.data.name, enable=False)
    gpool_query = GpoolParamsBase(
        host=request.device_info.management_ip,
        pool=[request.data.name],
    )

    _log_step(
        "delete_pool",
        "开始删除地址池",
        pool_name=request.data.name,
        management_ip=request.device_info.management_ip,
    )

    try:
        query_response = get_gpool(gpool_query, verify_ssl=False, auth=auth)
    except requests.RequestException as error:
        _log_exception("delete_pool", "调用 get_gpool 失败")
        return DeletePoolResponse(
            success=False,
            result=result,
            message=[f"查询地址池请求异常: {error}"],
        )

    if not query_response.ok:
        return DeletePoolResponse(
            success=False,
            result=result,
            message=[
                f"查询地址池失败, status={query_response.status_code}, body={query_response.text[:200]}"
            ],
        )

    try:
        resources = _parse_gpool_response(query_response)
    except (ValueError, json.JSONDecodeError) as error:
        _log_exception("delete_pool", "解析 get_gpool 返回失败")
        return DeletePoolResponse(
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
        return DeletePoolResponse(
            success=False,
            result=result,
            message=[f"未找到地址池 {request.data.name}"],
        )

    is_enabled = str(target_resource.get("enable", "")).lower() == "yes"
    members = target_resource.get("gmember_list", [])
    has_members = isinstance(members, list) and len(members) > 0

    if is_enabled and has_members:
        return DeletePoolResponse(
            success=False,
            result=result,
            message=[
                f"地址池 {request.data.name} 当前处于启用状态",
                f"地址池 {request.data.name} 仍存在 {len(members)} 个成员",
            ],
        )

    try:
        delete_request = _build_delete_gpool_request(
            request.device_info.management_ip,
            target_resource,
        )
    except ValueError as error:
        return DeletePoolResponse(
            success=False,
            result=result,
            message=[str(error)],
        )

    try:
        delete_response = delete_gpool(delete_request, verify_ssl=False, auth=auth)
    except requests.RequestException as error:
        _log_exception("delete_pool", "调用 delete_gpool 失败")
        return DeletePoolResponse(
            success=False,
            result=result,
            message=[f"删除地址池请求异常: {error}"],
        )

    if not delete_response.ok:
        return DeletePoolResponse(
            success=False,
            result=result,
            message=[
                f"删除地址池失败, status={delete_response.status_code}, body={delete_response.text[:200]}"
            ],
        )

    return DeletePoolResponse(
        success=True,
        result=result,
        message=[f"地址池 {request.data.name} 删除成功"],
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请提供 JSON 文件路径")
        sys.exit(1)

    input_json = sys.argv[1]
    with open(input_json, "r", encoding="utf-8") as file:
        input_data = json.load(file)

    result = delete_pool(input_data)
    print("\n******* Delete Pool Result *******")
    print(result.model_dump_json(indent=2, ensure_ascii=False))
