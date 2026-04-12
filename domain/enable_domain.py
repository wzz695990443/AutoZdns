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
### API: ADD 视图修改域名 ###


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


def put_gmap_record(
    req: GMapRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    动态域名解析修改记录
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

    response = requests.put(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("gmap", response)
    return response


############################################################
### API: default 视图修改域名 ###


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


def put_rrs_record(
    req: RrsRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    静态域名解析修改记录
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
        "rrs",
        "准备发送 RRS 请求",
        url=url,
        zone=zone_value,
        name=payload.get("name"),
        record_type=payload.get("type"),
        ttl=payload.get("ttl"),
        rdata_count=len(payload.get("rdata", [])),
    )

    response = requests.put(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("rrs", response)
    return response
