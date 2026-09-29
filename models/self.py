from typing import List, Optional, Dict, Any
from pydantic import BaseModel


class SystemInfo(BaseModel):
    hostname: str
    os: str
    os_release: str
    os_version: str
    architecture: str
    processor: str
    python_version: str
    platform: str


class GatewayInfo(BaseModel):
    ip: str
    interface: str


class HostRange(BaseModel):
    first: str
    last: str


class PortDetail(BaseModel):
    port: int
    service: str
    state: str
    bound_to: str


class PortsSummary(BaseModel):
    tcp: List[PortDetail]
    udp: List[PortDetail]


class ProtocolStatus(BaseModel):
    status: str
    open_count: Optional[int] = None


class IPv4Services(BaseModel):
    protocols: Dict[str, ProtocolStatus]
    ports: PortsSummary


class IPv6Services(BaseModel):
    protocols: Dict[str, ProtocolStatus]


class IPv4Detail(BaseModel):
    address: str
    type: str
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    cidr: Optional[str] = None
    network: Optional[str] = None
    prefix_length: Optional[int] = None
    host_range: Optional[HostRange] = None
    services: Optional[IPv4Services] = None


class IPv6Detail(BaseModel):
    address: str
    address_without_scope: str
    type: str
    netmask: Optional[str] = None
    services: Optional[IPv6Services] = None


class Interface(BaseModel):
    name: str
    ipv4: List[IPv4Detail]
    ipv6: List[IPv6Detail]
    mac: Optional[str] = None


class NetworkInfo(BaseModel):
    gateway: Optional[GatewayInfo] = None
    interfaces: List[Interface]


class NetCitySelfOutput(BaseModel):
    netcity_version: str
    system: SystemInfo
    network: NetworkInfo
