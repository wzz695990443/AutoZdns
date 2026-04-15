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
### API: DELETE GMap 记录 (动态域名) ###


class DeleteGMapRequest(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图必须是 ADD")
    zone: str = Field(..., description="域名区")
    name: str = Field(..., description="完整记录名")
    type: str = Field(..., alias="type", description="记录类型")


def delete_gmap_record(
    req: DeleteGMapRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    删除动态域名解析记录
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
        "gmap",
        "准备发送 GMap 删除请求",
        url=url,
        zone=zone_value,
        name=payload.get("name"),
        record_type=payload.get("type"),
    )

    response = requests.delete(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("gmap", response)
    return response


############################################################
### API: DELETE RRS 记录 (静态域名) ###


class DeleteRrsRequest(BaseModel):
    host: str = Field(..., description="主机 IP")
    view: str = Field(..., description="视图")
    zone: str = Field(..., description="域名区 (Zone)")
    name: str = Field(..., description="完整记录名 (如 www.test.com.)")
    type: str = Field(..., alias="type", description="记录类型")


def delete_rrs_record(
    req: DeleteRrsRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    删除静态域名解析记录
    通过 ZDNS API 删除 RRS (资源记录集) 记录。
    注意：body需要组合字符串格式，格式为 "name type"
    """

    payload = req.model_dump(by_alias=True, exclude_none=True)
    # 不属于 payload 的字段需在请求前剔除
    host_value = payload.pop("host", None)
    view_value = payload.pop("view", None)
    zone_value = payload.pop("zone", None)
    
    # 组合字符串: "name type"
    name_value = payload.get("name", "")
    type_value = payload.get("type", "")
    body_string = f"{name_value} {type_value}"

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
        "rrs",
        "准备发送 RRS 删除请求",
        url=url,
        zone=zone_value,
        name=name_value,
        record_type=type_value,
        body=body_string,
    )

    response = requests.delete(
        url, headers=headers, data=body_string, verify=verify_ssl, auth=auth
    )
    _log_http_response("rrs", response)
    return response


#############################################################
### 标准输入参数规范 ###


class DeviceInfo(BaseModel):
    management_ip: str = Field(..., description="管理节点 IP")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


class StaticRecord(BaseModel):
    name: str = Field(..., description="记录名称")
    type: str = Field(..., description="记录类型")


class DomainPoolRef(BaseModel):
    name: str = Field(..., description="地址池名称")


class DynamicDomainInfo(BaseModel):
    name: str = Field(..., description="域名")
    type: Literal["dynamic"] = Field(default="dynamic", description="域名解析方式")
    records: List[str] = Field(..., description="记录类型列表 (如 ['A', 'AAAA'])")


class StaticDomainInfo(BaseModel):
    name: str = Field(..., description="域名")
    type: Literal["static"] = Field(default="static", description="域名解析方式")
    records: List[StaticRecord] = Field(..., description="记录列表")


class DeleteDomainRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: Literal["delete_domain"] = Field(..., description="操作类型")
    data: Annotated[
        Union[DynamicDomainInfo, StaticDomainInfo],
        Field(discriminator="type"),
    ]


#############################################################
### 标准返回值规范 ###

DomainResult = Annotated[
    Union[DynamicDomainInfo, StaticDomainInfo],
    Field(discriminator="type"),
]


class DeleteDomainResponse(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: Optional[DomainResult] = Field(default=None, description="返回的域名信息")
    message: List[str] = Field(..., description="操作结果消息")


#############################################################
### 辅助函数 ###


def _ensure_fqdn(name: str) -> str:
    """
    确保域名以点 (.) 结尾，形成完全限定域名 (FQDN)。
    """
    if not name.endswith("."):
        return name + "."
    return name


def _build_dynamic_zone_name(name: str) -> str:
    """
    从完整域名中提取动态区域名称。
    例如：www.test.com -> test.com
    """
    parts = name.split(".")
    return ".".join(parts[-2:])


def _build_static_zone_name(name: str) -> str:
    """
    从完整域名中提取静态区域名称。
    例如：www.test.com -> test.com
    """
    parts = name.split(".")
    return ".".join(parts[-2:])


def _build_record_name(record_name: str, domain_name: str) -> str:
    """
    构建完整记录名称
    如果 record_name 是 @，则使用域名本身
    否则，组合记录名和域名
    """
    if record_name == "@":
        return _ensure_fqdn(domain_name)
    
    if "." in record_name:
        # 如果记录名已经包含域名，直接使用
        return _ensure_fqdn(record_name)
    
    # 组合记录名和域名
    return _ensure_fqdn(f"{record_name}.{domain_name}")


def _build_delete_domain_response(
    success: bool,
    message: List[str],
    result: Optional[Union[DynamicDomainInfo, StaticDomainInfo]] = None,
) -> DeleteDomainResponse:
    return DeleteDomainResponse(success=success, result=result, message=message)


def delete_domain(data: Dict[str, Any]) -> DeleteDomainResponse:
    """
    删除域名记录
    逻辑说明：
    1. 验证输入数据结构和内容。
    2. 根据域名类型（dynamic 或 static）执行不同的处理流程。
    3. 对于 dynamic 域名，调用 delete_gmap_record 删除 GMap 记录。
    4. 对于 static 域名，调用 delete_rrs_record 删除 RRS 记录。
    5. 捕获并返回任何验证错误或请求异常，确保函数的健壮性。
    """
    _log_step("delete-domain", "开始处理 delete_domain 请求", input_data=data)

    try:
        request = DeleteDomainRequest.model_validate(data)
    except ValidationError as error:
        _log_step("delete-domain", "输入校验失败", errors=error.errors())
        return _build_delete_domain_response(
            success=False,
            message=[error.json(indent=2)],
        )

    auth = (request.device_info.username, request.device_info.password)
    record_fqdn = _ensure_fqdn(request.data.name)
    dynamic_zone_name = _build_dynamic_zone_name(request.data.name)
    static_zone_name = _build_static_zone_name(request.data.name)
    _log_step(
        "delete-domain",
        "输入校验成功",
        domain_type=request.data.type,
        record_fqdn=record_fqdn,
        dynamic_zone_name=dynamic_zone_name,
        static_zone_name=static_zone_name,
    )

    try:
        if isinstance(request.data, DynamicDomainInfo):
            _log_step(
                "delete-domain",
                "进入 dynamic 域名处理分支",
                domain_name=request.data.name,
                record_types=request.data.records,
            )

            responses: List[str] = []
            success = True
            
            for record_type in request.data.records:
                _log_step(
                    "delete-domain",
                    "准备发送动态域名删除请求",
                    record_type=record_type,
                )

                gmap_request = DeleteGMapRequest(
                    host=request.device_info.management_ip,
                    zone=dynamic_zone_name,
                    name=record_fqdn,
                    type=record_type,
                )
                response = delete_gmap_record(req=gmap_request, auth=auth)
                response_text = response.text.strip() or "无返回内容"
                responses.append(
                    f"{record_fqdn} {record_type}: {response.status_code} - {response_text}"
                )
                if not response.ok:
                    success = False

            _log_step(
                "delete-domain",
                "dynamic 域名处理完成",
                success=success,
                responses=responses,
            )
            return _build_delete_domain_response(
                success=success,
                result=request.data,
                message=responses,
            )

        elif isinstance(request.data, StaticDomainInfo):
            _log_step(
                "delete-domain",
                "进入 static 域名处理分支",
                domain_name=request.data.name,
                records=request.data.records,
            )

            responses: List[str] = []
            success = True
            
            for record in request.data.records:
                record_name = _build_record_name(record.name, request.data.name)
                _log_step(
                    "delete-domain",
                    "准备发送静态域名删除请求",
                    record_name=record_name,
                    record_type=record.type,
                )
                
                rrs_request = DeleteRrsRequest(
                    host=request.device_info.management_ip,
                    view="default",
                    zone=static_zone_name,
                    name=record_name,
                    type=record.type,
                )
                response = delete_rrs_record(req=rrs_request, auth=auth)
                response_text = response.text.strip() or "无返回内容"
                responses.append(
                    f"{record_name} {record.type}: {response.status_code} - {response_text}"
                )
                if not response.ok:
                    success = False

            _log_step(
                "delete-domain",
                "static 域名处理完成",
                success=success,
                responses=responses,
            )
            return _build_delete_domain_response(
                success=success,
                result=request.data,
                message=responses,
            )
    except (ValidationError, ValueError) as error:
        _log_exception("delete-domain", f"处理 delete_domain 时发生校验或值错误: {error}")
        return _build_delete_domain_response(
            success=False,
            result=request.data,
            message=[str(error)],
        )
    except requests.RequestException as error:
        _log_exception("delete-domain", f"处理 delete_domain 时发生请求异常: {error}")
        return _build_delete_domain_response(
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

    result = delete_domain(input_data)
    print("\n******* Delete Domain Result *******")
    print(result.model_dump_json(indent=2, ensure_ascii=False))
