import requests
import urllib3
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ValidationError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GPoolItem(BaseModel):
    id: str
    gpool_name: str
    ratio: str = Field("1", description="权重")


class GMapRequest(BaseModel):
    # 下列字段为必填项 (不提供默认值)
    host: str = Field(..., description="主机 IP")
    view: str = Field(..., description="视图")
    zone: str = Field(..., description="域名区 (Zone)")
    name: str = Field(..., description="完整记录名 (如 www.test.com.)")
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


def create_gmap_record(
    req: GMapRequest, verify_ssl: bool = False, auth: tuple = ("admin", "Admin@123")
) -> requests.Response:
    """
    通过 ZDNS API 创建或修改 GMap (全局映射) 记录。
    """
    url = f"https://{req.host}:20120/views/{req.view}/dzone/{req.zone}/gmap"

    headers = {
        "Request-By": "AXIOS",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Referer": f"https://{req.host}/",
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Microsoft Edge";v="146"',
        "sec-ch-ua-mobile": "?0",
        # 不用在这里手动写 Authorization，requests 会根据 auth 参数自动生成
    }

    # 获取验证后的字典数据，并排除未赋值的选填项
    payload = req.model_dump(by_alias=True, exclude_none=True)
    # 不属于 payload 的字段需在请求前剔除
    host_value = payload.pop("host", None)
    view_value = payload.pop("view", None)
    zone_value = payload.pop("zone", None)

    # 发送请求时，加上 auth=auth 参数
    response = requests.post(
        url, headers=headers, json=payload, verify=verify_ssl, auth=auth
    )
    return response

class DeviceInfo(BaseModel):
    management_ip: str = Field(..., description="管理节点 IP")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")
    

class AddDomainRequest(BaseModel):
    device_info: DeviceInfo = Field(..., description="设备信息")
    operation: str = Field(..., description="操作类型")
    domain: bool = Field(..., description="是否启用")




if __name__ == "__main__":
    try:
        req_data = GMapRequest(
            host="10.1.114.14",
            view="ADD",
            zone="test.com.",
            name="aaa.test.com.",
            type="A",
            algorithm="rr",
            gpool_list=[
                GPoolItem(id="_id1", gpool_name="DC-A", ratio="1"),
                GPoolItem(id="_id2", gpool_name="DC-B", ratio="1"),
            ],
            fail_policy="return_add_rrs",
            failure_response_rrs_ttl=5,
            failure_response_soa_ttl=5,
            enable="yes",
        )
        res = create_gmap_record(req=req_data)
        print("Status Code:", res.status_code)
        print("Response:", res.text)
    except ValidationError as e:
        print("输入验证失败:")
        print(e.json(indent=2))
