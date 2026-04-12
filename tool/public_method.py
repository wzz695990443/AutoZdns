def ip_analysis(vlaue: str):
    record = {"dc": "", "operator": ""}
    message = ""
    return {"record": record, "message": message}


def service_name(record_vlaue: str, port: int) -> str:
    """_summary_
    通过输入参数返回服务成员标准名称
    Args:
        record_vlaue (str): _description_
        port (int): _description_

    Returns:
        str: _description_
    """
    return record_vlaue + "_" + str(port)


def pool_name(
    domain_name: str, port: int, record_type: str, region: str = "", operator: str = ""
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
    return domain_name + "_" + region + "_" + operator + "_pool_" + record_type

def generate_pool_name(request: dict) -> dict:
    domain_name = request.get("domain", {}).get("name", "")
    pool_data = request.get("pool", {})
    record_type = pool_data.get("type", "A")
    first_algo = pool_data.get("first_algorithm", "")
    ip_value = pool_data.get("record", {}).get("value", "")

    v_type = "v4" if record_type == "A" else "v6" if record_type == "AAAA" else "v4"
    
    if first_algo == "topology":
        ip_info = ip_analysis(ip_value)
        record_info = ip_info.get("record", {})
        dc = record_info.get("dc", "")
        operator = record_info.get("operator", "")
        
        # 若为内网且为HF(合肥)中心，则标识为hf；若为公网且为联通(cu)，则标识为cu
        tag = dc if dc else operator
        if tag:
            result = f"{domain_name}_{tag}_{v_type}_pool"
        else:
            result = f"{domain_name}_{v_type}_pool"
    else:
        result = f"{domain_name}_{v_type}_pool"

    return {
        "result": result,
        "messages": {}
    }

