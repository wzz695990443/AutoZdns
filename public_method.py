def record_name(record_vlaue: str,port: int,record_type: str) -> str:
    return "A"

def service_name(record_vlaue: str,port: int,record_type: str) -> str:
    """_summary_
    通过输入参数返回服务成员标准名称
    Args:
        record_vlaue (str): _description_
        port (int): _description_
        record_type (str): _description_

    Returns:
        str: _description_
    """
    return record_vlaue + "_" + str(port)


def pool_name(
    domain_name: str, port: int, record_type: str, region: str = '', operator: str = ''
) -> str:
    """_summary_
    通过输入参数返回全局地址池标准名称
    Args:
        domain_name (str): _description_
        port (int): _description_
        record_type (str): _description_
        region (str, optional): _description_. Defaults to ''.
        operator (str, optional): _description_. Defaults to ''.

    Returns:
        str: _description_


    """
    if record_type == "A":
        record_type = "v4"
    elif record_type == "AAAA":
        record_type = "v6"
    return domain_name + "_" +region + "_" + operator + "_pool_" + record_type
