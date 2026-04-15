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

class DeviceInfoBase(BaseModel):
    management_ip: str = Field(..., description="管理节点 IP")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")

class ConditionsBase(BaseModel):
    field: str = Field(..., description="查询字段")
    value: str = Field(..., description="查询值")
    type: str = Field(default="", description="记录类型")
    match_type: Optional[str] = Field(default="fuzzy", description="匹配类型，exact 或 fuzzy")

class OrderBase(BaseModel):
    order_key: str = Field(..., description="排序字段")
    order_type: Literal["asc", "desc"] = Field(..., description="排序方向，asc 或 desc")

class QueryDomainBase(BaseModel):
    device_info: DeviceInfoBase = Field(..., description="设备信息")
    operation: Literal["query_domain"] = Field(..., description="操作类型")
    conditions: ConditionsBase = Field(..., description="查询条件") 
    orders: OrderBase = Field(..., description="排序规则列表")

#############################################################
### 标准输出规范 ###

class RecordBase(BaseModel):
    name: str = Field(..., description="记录名称")
    value: str = Field(..., description="记录值")
    enable: str = Field(..., description="是否启用")
    dc: str = Field(..., description="数据中心")
    weight: Optional[int] = Field(default=None, description="权重")

class PoolBase(BaseModel):
    name: str = Field(..., description="地址池名称")
    enable: str = Field(..., description="地址池是否启用")
    type: str = Field(..., description="地址池类型")
    records: List[RecordBase] = Field(default_factory=list, description="地址池成员列表")
    health_check: Optional[Dict[str, Any]] = Field(default=None, description="健康检查配置")
    first_algorithm: Optional[str] = Field(default=None, description="首选算法")
    second_algorithm: Optional[str] = Field(default=None, description="次选算法")

class DomainResultBase(BaseModel):
    name: str = Field(..., description="记录名称")
    type: str = Field(..., description="记录类型")
    algorithm: Optional[str] = Field(default=None, description="负载均衡算法")
    enable: Optional[str] = Field(default=None, description="是否启用")
    ttl: Optional[int] = Field(default=None, description="TTL")
    pools: PoolBase = Field(..., description="关联的地址池列表")

class QueryDomainResponseBase(BaseModel):
    success: bool = Field(..., description="操作是否成功")
    result: DomainResultBase = Field(..., description="返回的域名信息")
    message: List[str] = Field(..., description="操作结果消息")


#############################################################
### API: 动态域名查询 ###


class GMapQueryParams(BaseModel):
    # 下列字段为必填项 (不提供默认值)
    host: str = Field(..., description="主机 IP")
    view: Literal["ADD"] = Field(default="ADD", description="视图必须是 ADD")
    zone: str = Field(..., description="域名区")
    search_attrs: List[List[str]] = Field(..., description="搜索属性嵌套列表")
    version: int = 2


def  get_gmap_record(
    pld: GMapQueryParams, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    动态域名解析查询记录
    通过 ZDNS API 查询 GMap (全局映射) 记录。
    """

    payload = pld.model_dump(by_alias=True, exclude_none=True)
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
        "get gmap",
        "准备发送 Get 请求",
        url=url,
        zone=zone_value,
    )

    response = requests.get(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    _log_http_response("gmap", response)
    return response

    """
    {"resources":[{"id":"ccc.test.com.$A","name":"ccc.test.com.","alias_name_count":0,"alias_name":"ccc.test.com.","type":"A","name_to_unicode":"ccc.test.com.","name_to_ascii":"ccc.test.com.","enable":"no","algorithm":"wrr","last_resort_pool":"","fail_policy":"return_add_rrs","persist_enable":"no","persist_time":"60","failure_response_rrs_ttl":"5","failure_response_soa_ttl":"5","gpool_list":[{"gpool_name":"DC-A","ratio":"1"},{"gpool_name":"DC-B","ratio":"1"}],"daemon_id":"","_foreignerdzone":2,"sp_name":"","real_id":12,"key_1":"","status":"BLACK","last_status":"GREEN"},{"id":"ccc.test.com.$AAAA","name":"ccc.test.com.","alias_name_count":0,"alias_name":"ccc.test.com.","type":"AAAA","name_to_unicode":"ccc.test.com.","name_to_ascii":"ccc.test.com.","enable":"no","algorithm":"wrr","last_resort_pool":"","fail_policy":"return_add_rrs","persist_enable":"no","persist_time":"60","failure_response_rrs_ttl":"5","failure_response_soa_ttl":"5","gpool_list":[{"gpool_name":"DC-A-v6","ratio":"1"}],"daemon_id":"","_foreignerdzone":2,"sp_name":"","real_id":13,"key_1":"","status":"BLACK","last_status":"GREEN"}],"page_num":"1","page_size":"30","total_size":"2","display_attrs":{"id":"gmap_in_add","user":"admin","res_type":"gmap_in_add","display":"{\"display_version\":\"v1.0\",\"is_check_data\":true,\"schema\":{\"status\":{\"width\":0.1},\"name\":{\"width\":0.18324468085106385},\"alias_name_count\":{\"width\":0.1},\"type\":{\"width\":0.1},\"algorithm\":{\"width\":0.1},\"sp_name\":{\"width\":0.1},\"gpool_list\":{\"width\":0.1},\"last_resort_pool\":{\"width\":0.1},\"failure_response_rrs_ttl\":{\"width\":0.1},\"failure_response_soa_ttl\":{\"width\":0.1},\"fail_policy\":{\"width\":0.1},\"enable\":{\"width\":0.1},\"key_1\":{\"width\":0.1}}}","attrs":[{"id":"key_1","type":"text","display_name":"备注","component_type":"single_line_text","option_values":""}],"private_attrs":{"id":"gmap_in_add","res_type":"gmap_in_add","module_type":"ADD","attrs":["key_1"]}}}
    """

#############################################################

if __name__ == "__main__":
    gqp = GMapQueryParams(
        host="20.200.18.82",
        view="ADD",
        zone="psbc.com",
        search_attrs=[["name", "eq","www.test.com.","and"]]
    )
    auth = ("admin", "Admin@123")
    result = get_gmap_record(gqp, auth=auth)
    print(result.status_code)
    print(result.text)
