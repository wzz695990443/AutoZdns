from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class DNSNode(BaseModel):
    """DNS服务节点"""

    node_ip: str = Field(..., description="DNS服务节点IP")
    qps: int = Field(..., description="DNS服务节点qps")
    enabled: bool = Field(..., description="是否启用")


class DomainRecordRef(BaseModel):
    """静态域名关联的Record引用"""

    value: str = Field(..., description="记录值")


class HealthCheck(BaseModel):
    """Pool健康检查"""

    type: Literal["tcp", "udp", "icmp"] = Field(..., description="健康检查类型")
    port: int = Field(..., description="健康检查端口")


class Record(BaseModel):
    """记录对象"""

    name: str = Field(..., description="记录名称")
    type: str = Field(..., description="类型")
    value: str = Field(..., description="记录值")
    port: Optional[int] = Field(None, description="端口")
    weight: Optional[int] = Field(None, description="权重")
    enabled: bool = Field(..., description="是否启用")
    dc: str = Field(..., description="所属数据中心")


class Pool(BaseModel):
    """地址池 (Pool)"""

    name: str = Field(..., description="pool名称")
    type: Literal["A", "AAAA"] = Field(..., description="域名类型")
    enabled: bool = Field(..., description="是否启用")
    records: List[Record] = Field(
        default_factory=list, description="服务成员列表"
    )
    health_check: Optional[HealthCheck] = Field(None, description="健康检查配置")
    first_algorithm: Literal["rr", "wrr", "topology", "none"] = Field(
        "wrr", description="Pool首选算法"
    )
    second_algorithm: Literal["rr", "wrr", "topology", "none"] = Field(
        "none", description="Pool次选算法"
    )


class Domain(BaseModel):
    """域名对象"""

    name: str = Field(..., description="域名")
    type: Literal["dynamic", "static", "all"] = Field(
        ..., description="域名类型：dynamic、static、all"
    )
    enabled: bool = Field(..., description="是否启用")
    algorithm: Optional[Literal["rr", "wrr", "topology", "none"]] = Field(
        "rr", description="域名算法"
    )
    ttl: int = Field(..., description="ttl")
    pools: Optional[List[Pool]] = Field(None, description="域名类型为dynamic关联的pool")
    records: Optional[List[DomainRecordRef]] = Field(
        None, description="域名类型为static关联的record"
    )
