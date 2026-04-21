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


def main() -> int:
    input_path = (
        sys.argv[1] if len(sys.argv) > 1 else _default_input_path("add_record.json")
    )
    _log_step("main", "脚本启动", input_path=input_path, log_file=LOG_FILE)

    try:
        input_data = _load_input_data(input_path)
    except (OSError, json.JSONDecodeError) as exc:
        _log_exception("main", f"读取输入文件失败: {input_path}")
        _print_cli_error(f"读取输入文件失败: {exc}")
        return 1

    result = add_gmember(input_data)
    _log_step("main", "脚本执行完成", success=result.success)
    _print_cli_result(result)
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
