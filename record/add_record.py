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
logger = logging.getLogger("autozdns.add_record")


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
    port: int = Field(..., description="端口")

    @model_validator(mode="after")
    def fill_name(self):
        if self.name == "":
            self.name = f"{self.value}_{self.port}"
        return self


class AddRecordRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["add_record", "create_record"] = Field(
        ..., description="操作类型"
    )
    data: List[DataBase] = Field(..., description="要添加的记录列表")


#############################################################
### 标准输出规范 ###


class AddRecordResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: List[DataBase] = Field(default_factory=list, description="操作结果数据")
    message: List[str] = Field(default_factory=list, description="操作结果消息")


#############################################################
### API: 新增服务记录 ###


class GmemberRequestBase(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str = Field(..., description="设备管理IP")
    dc: str = Field(..., description="数据中心名称")
    gmember_name: str = Field(default="", description="gmember名称")
    ip: str = Field(..., description="IP地址")
    port: int = Field(..., description="端口号")
    hms: List[str] = Field(default_factory=list, description="健康检查方式列表")
    pass_: str = Field(default="", alias="pass", description="无具体作用")
    link_id: str = Field(default="", description="链路策略ID，默认为空字符串")
    preferred_prober: str = Field(default="", description="首选探测器，默认为空字符串")
    alternate_prober: str = Field(default="", description="备用探测器，默认为空字符串")
    enable: str = Field(default="yes", description="是否启用，默认为yes")
    key_1: str = Field(default="", alias="key_1", description="备注")

    @model_validator(mode="after")
    def fill_gmember_name(self):
        if self.gmember_name == "":
            self.gmember_name = f"{self.ip}_{self.port}"
        return self


def post_gmember(
    req: GmemberRequestBase,
    verify_ssl: bool = False,
    auth: tuple = ("admin", "Admin@123"),
) -> requests.Response:
    """
    API:新增Gmember服务成员
    """
    payload = req.model_dump(by_alias=True, exclude_none=True)
    # 不属于 payload 的字段需在请求前剔除
    host_value = payload.pop("host", None)
    dc_value = payload.pop("dc", None)

    url = f"https://{host_value}:20120/dc/{dc_value}/gmember"

    headers = {
        "Request-By": "Python-Requests",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{host_value}/",
        "sec-ch-ua-platform": '"Python-API"',
        "sec-ch-ua": '"Python-API"',
        "X-Requested-With": "XMLHttpRequest",
    }
    _log_step("post_gmember", "准备发送新增Gmember服务成员请求", url=url, dc=dc_value)
    response = requests.post(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("post_gmember", response)
    return response


#############################################################
### 增加服务成员核心逻辑 ###


def _build_dc_name(management_ip: str) -> str:
    """
    构建数据中心名称,通过IP地址库判断属于哪个数据中心
    目前没有具体的IP地址库,暂时返回一个固定值
    """
    return "HF"


def _build_gmember_request(
    request: AddRecordRequest, item: DataBase
) -> GmemberRequestBase:
    return GmemberRequestBase(
        host=request.device_info.management_ip,
        dc=_build_dc_name(request.device_info.management_ip),
        gmember_name=item.name,
        ip=item.value,
        port=item.port,
        hms=[],
    )


def add_gmember(data: Dict[str, Any]) -> AddRecordResponse:
    """
    核心逻辑：新增Gmember服务成员
    """
    try:
        request = AddRecordRequest.model_validate(data)
    except ValidationError as e:
        _log_exception("add_gmember", "AddRecordRequest 数据验证失败")
        return AddRecordResponse(success=False, message=[str(e)])

    auth = (request.device_info.username, request.device_info.password)
    result: List[DataBase] = []
    messages: List[str] = []
    success = True

    _log_step(
        "add_gmember",
        "开始批量新增 Gmember",
        count=len(request.data),
        management_ip=request.device_info.management_ip,
    )

    for item in request.data:
        gmember_request = _build_gmember_request(request, item)

        _log_step(
            "add_gmember",
            "转换记录为 Gmember 请求",
            gmember_name=gmember_request.gmember_name,
            ip=gmember_request.ip,
            port=gmember_request.port,
            dc=gmember_request.dc,
        )

        try:
            response = post_gmember(
                gmember_request,
                verify_ssl=False,
                auth=auth,
            )
        except requests.RequestException as e:
            success = False
            _log_exception("add_gmember", "调用 post_gmember 失败")
            messages.append(f"{gmember_request.gmember_name}: 请求异常: {e}")
            continue

        if response.ok:
            result.append(item)
            messages.append(f"{gmember_request.gmember_name}: 创建成功")
            continue

        success = False
        messages.append(
            f"{gmember_request.gmember_name}: 创建失败, status={response.status_code}, body={response.text[:200]}"
        )

    return AddRecordResponse(success=success, result=result, message=messages)


#############################################################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请提供 JSON 文件路径")
        sys.exit(1)

    input_json = sys.argv[1]
    with open(input_json, "r", encoding="utf-8") as file:
        input_data = json.load(file)

    result = add_gmember(input_data)
    print("\n******* Add Gmember Result *******")
    print(result.model_dump_json(indent=2, ensure_ascii=False))
