import requests
import re
import json
import base64
import time
import yaml

# 配置
SURGE_CONF_PATH = "surge_snell.conf"
SEARCH_QUERIES = [
    "snell psk version",
    "snell config",
    "surge snell",
    "snell server",
    "snell extension:.txt",
    "snell extension:.json",
    "snell extension:.yaml",
    "proxy snell",
    "vpn snell",
    "snell fork:true",
    "snell language:yaml",
    "snell language:json"
]
PER_PAGE = 30
MAX_PAGES = 7
GIST_MAX_PAGES = 3

def get_github_token(attempt=1, max_attempts=3):
    """从终端获取 GitHub Token，支持重试"""
    if attempt > max_attempts:
        raise ValueError("重试次数过多，程序退出")
    
    token = input(f"请输入你的 GitHub Personal Access Token (尝试 {attempt}/{max_attempts}): ").strip()
    if not token:
        raise ValueError("Token 不能为空！")
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        response = requests.get("https://api.github.com/user", headers=headers)
        if response.status_code == 401:
            print("401 错误：Token 无效或无权限，请检查 Token 是否正确或已过期")
            return get_github_token(attempt + 1, max_attempts)
        response.raise_for_status()
        scopes = response.headers.get("X-OAuth-Scopes", "")
        if "repo" not in scopes or "gist" not in scopes:
            print("错误：Token 缺少 'repo' 或 'gist' 权限，请重新生成 Token")
            return get_github_token(attempt + 1, max_attempts)
        return token
    except requests.RequestException as e:
        print(f"验证 Token 失败: {e}")
        return get_github_token(attempt + 1, max_attempts)

def search_github_files(query, headers):
    """搜索 GitHub 文件"""
    nodes = []
    for page in range(1, MAX_PAGES + 1):
        url = f"https://api.github.com/search/code?q={query}&per_page={PER_PAGE}&page={page}"
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 401:
                raise ValueError("401 错误：Token 无效，请重新运行程序")
            response.raise_for_status()
            data = response.json()
            for item in data.get("items", []):
                repo = item["repository"]["full_name"]
                path = item["path"]
                file_url = item["url"]
                nodes.append({"repo": repo, "path": path, "file_url": file_url})
            time.sleep(1)
        except requests.RequestException as e:
            print(f"搜索 '{query}' 失败: {e}")
            break
    return nodes

def search_github_gists(headers):
    """搜索 GitHub Gists"""
    nodes = []
    for page in range(1, GIST_MAX_PAGES + 1):
        url = "https://api.github.com/gists/public"
        try:
            response = requests.get(url, headers=headers, params={"per_page": PER_PAGE, "page": page})
            if response.status_code == 401:
                raise ValueError("401 错误：Token 无效，请重新运行程序")
            response.raise_for_status()
            gists = response.json()
            for gist in gists:
                for filename, file_info in gist["files"].items():
                    if any(keyword in filename.lower() for keyword in ["snell", "proxy", "config", "surge"]):
                        nodes.append({
                            "repo": gist["id"],
                            "path": filename,
                            "file_url": file_info["raw_url"]
                        })
            time.sleep(1)
        except requests.RequestException as e:
            print(f"Gist 搜索 (页 {page}) 失败: {e}")
            break
    return nodes

def search_commit_messages(headers):
    """搜索提交消息"""
    nodes = []
    url = "https://api.github.com/search/commits?q=snell+config&per_page=30"
    try:
        response = requests.get(url, headers={**headers, "Accept": "application/vnd.github.cloak-preview+json"})
        if response.status_code == 401:
            raise ValueError("401 错误：Token 无效，请重新运行程序")
        response.raise_for_status()
        commits = response.json().get("items", [])
        for commit in commits:
            repo = commit["repository"]["full_name"]
            files_url = f"https://api.github.com/repos/{repo}/contents"
            try:
                file_response = requests.get(files_url, headers=headers)
                file_response.raise_for_status()
                for file in file_response.json():
                    if file["type"] == "file" and any(ext in file["name"] for ext in [".txt", ".json", ".yaml"]):
                        nodes.append({
                            "repo": repo,
                            "path": file["name"],
                            "file_url": file["download_url"] or file["url"]
                        })
            except requests.RequestException:
                continue
        time.sleep(1)
    except requests.RequestException as e:
        print(f"提交消息搜索失败: {e}")
    return nodes

def get_file_content(file_url, headers):
    """获取文件内容"""
    try:
        if "raw.githubusercontent" in file_url or "download_url" in file_url:
            response = requests.get(file_url)
        else:
            response = requests.get(file_url, headers=headers)
        if response.status_code == 401:
            raise ValueError("401 错误：Token 无效，请重新运行程序")
        response.raise_for_status()
        if "raw.githubusercontent" in file_url or "download_url" in file_url:
            return response.text
        file_data = response.json()
        return base64.b64decode(file_data["content"]).decode("utf-8", errors="ignore")
    except requests.RequestException as e:
        print(f"获取文件内容失败: {e}")
        return None

def parse_snell_nodes(content, node_counter):
    """解析 Snell 节点信息，返回节点和更新后的计数器"""
    nodes = []
    
    # 正则表达式匹配 Surge 格式
    pattern = r"(?:(?:[\w\-]+)\s*=\s*)?snell\s*,\s*([\w\.\-]+)\s*,\s*(\d+)\s*,\s*psk\s*=\s*([\w\=]+)(?:\s*,\s*version\s*=\s*(\d+))?(?:\s*,\s*obfs\s*=\s*(\w+))?(?:\s*,\s*obfs-host\s*=\s*([\w\.\-]+))?"
    matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
    
    for match in matches:
        server = match[0]
        port = match[1]
        psk = match[2]
        version = match[3] if match[3] else "4"
        obfs = match[4] if match[4] else "none"
        obfs_host = match[5] if match[5] else ""
        
        node = {
            "name": f"Snell_{node_counter}",
            "server": server,
            "port": port,
            "psk": psk,
            "version": version,
            "obfs": obfs,
            "obfs_host": obfs_host
        }
        nodes.append(node)
        node_counter += 1
    
    # 解析 Base64 编码的 Snell 链接
    base64_pattern = r"snell://([A-Za-z0-9+/=]+)"
    base64_matches = re.findall(base64_pattern, content)
    for match in base64_matches:
        try:
            decoded = base64.b64decode(match).decode("utf-8")
            parts = decoded.split("#")
            if len(parts) >= 2:
                server_port = parts[0].split(":")
                if len(server_port) == 2:
                    nodes.append({
                        "name": f"Snell_{node_counter}",
                        "server": server_port[0],
                        "port": server_port[1],
                        "psk": parts[1],
                        "version": "4",
                        "obfs": "none",
                        "obfs_host": ""
                    })
                    node_counter += 1
        except Exception:
            continue
    
    # 解析 JSON 格式
    try:
        json_data = json.loads(content)
        if isinstance(json_data, list):
            for item in json_data:
                if "server" in item and "psk" in item:
                    nodes.append({
                        "name": item.get("name", f"Snell_{node_counter}"),
                        "server": item["server"],
                        "port": str(item.get("port", "443")),
                        "psk": item["psk"],
                        "version": str(item.get("version", "4")),
                        "obfs": item.get("obfs", "none"),
                        "obfs_host": item.get("obfs_host", "")
                    })
                    node_counter += 1
        elif isinstance(json_data, dict) and "snell" in json_data:
            for item in json_data["snell"]:
                nodes.append({
                    "name": item.get("name", f"Snell_{node_counter}"),
                    "server": item["server"],
                    "port": str(item.get("port", "443")),
                    "psk": item["psk"],
                    "version": str(item.get("version", "4")),
                    "obfs": item.get("obfs", "none"),
                    "obfs_host": item.get("obfs_host", "")
                })
                node_counter += 1
    except json.JSONDecodeError:
        pass
    
    # 解析 YAML 格式
    try:
        yaml_data = yaml.safe_load(content)
        if isinstance(yaml_data, list):
            for item in yaml_data:
                if "server" in item and "psk" in item:
                    nodes.append({
                        "name": item.get("name", f"Snell_{node_counter}"),
                        "server": item["server"],
                        "port": str(item.get("port", "443")),
                        "psk": item["psk"],
                        "version": str(item.get("version", "4")),
                        "obfs": item.get("obfs", "none"),
                        "obfs_host": item.get("obfs_host", "")
                    })
                    node_counter += 1
        elif isinstance(yaml_data, dict) and "snell" in yaml_data:
            for item in yaml_data["snell"]:
                nodes.append({
                    "name": item.get("name", f"Snell_{node_counter}"),
                    "server": item["server"],
                    "port": str(item.get("port", "443")),
                    "psk": item["psk"],
                    "version": str(item.get("version", "4")),
                    "obfs": item.get("obfs", "none"),
                    "obfs_host": item.get("obfs_host", "")
                })
                node_counter += 1
    except yaml.YAMLError:
        pass
    
    return nodes, node_counter

def generate_surge_config(nodes):
    """生成 Surge 配置文件"""
    # [General] 部分，参考用户提供的配置
    general_section = [
        "[General]",
        "dns-server = 8.8.8.8, 8.8.4.4, system",
        "ipv6 = true",
        "test-timeout = 5",
        "loglevel = notify",
        "use-local-host-item-for-proxy = true",
        "proxy-restricted-to-lan = false",
        "http-listen = 0.0.0.0",
        "socks5-listen = 0.0.0.0",
        ""
    ]
    
    # [Proxy] 部分
    proxy_section = ["[Proxy]"]
    seen = set()  # 去重节点
    name_check = set()  # 检测重复名称
    proxy_names = []  # 存储节点名称用于 Proxy Group
    for node in nodes:
        node_key = (node["server"], node["port"], node["psk"])
        if node_key not in seen:
            seen.add(node_key)
            if node["name"] in name_check:
                base_name = node["name"]
                suffix = 1
                while f"{base_name}_{suffix}" in name_check:
                    suffix += 1
                node["name"] = f"{base_name}_{suffix}"
            name_check.add(node["name"])
            proxy_names.append(node["name"])
            line = f"{node['name']} = snell, {node['server']}, {node['port']}, psk={node['psk']}, version={node['version']}"
            if node['obfs'] != "none":
                line += f", obfs={node['obfs']}"
                if node['obfs_host']:
                    line += f", obfs-host={node['obfs_host']}"
            proxy_section.append(line)
    
    # [Proxy Group] 部分，动态包含扫描到的节点
    proxy_group_section = [
        "[Proxy Group]",
        f"Stable = fallback, {', '.join(proxy_names)}" if proxy_names else "Stable = fallback, DIRECT",
        f"Auto = select, {', '.join(proxy_names)}" if proxy_names else "Auto = select, DIRECT",
        "Proxy = select, DIRECT, " + ", ".join(proxy_names) if proxy_names else "Proxy = select, DIRECT",
        "China = select, DIRECT, " + ", ".join(proxy_names) if proxy_names else "China = select, DIRECT",
        "Media = select, " + ", ".join(proxy_names) if proxy_names else "Media = select, DIRECT",
        "Reject = select, REJECT, DIRECT",
        ""
    ]
    
    # [Rule] 部分，简化版参考用户配置
    rule_section = [
        "[Rule]",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-SUFFIX,com.cn,DIRECT",
        "DOMAIN-SUFFIX,org.cn,DIRECT",
        "DOMAIN-SUFFIX,gov.cn,DIRECT",
        "DOMAIN-SUFFIX,edu.cn,DIRECT",
        "DOMAIN,qq.com,DIRECT",
        "DOMAIN,weixin.qq.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,netflix.com,Media",
        "DOMAIN-SUFFIX,youtube.com,Media",
        "DOMAIN-SUFFIX,apple.com,Proxy",
        "GEOIP,CN,China",
        "GEOIP,US,Proxy",
        "FINAL,Stable",
        ""
    ]
    
    return "\n".join(general_section + proxy_section + proxy_group_section + rule_section)

def save_config(content):
    """保存配置文件"""
    with open(SURGE_CONF_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"配置文件已保存到: {SURGE_CONF_PATH}")

def main():
    try:
        # 获取用户输入的 Token
        GITHUB_TOKEN = get_github_token()
        HEADERS = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        print("开始搜索 Snell 节点...")
        all_files = []
        
        # 搜索 GitHub 仓库文件
        for query in SEARCH_QUERIES:
            print(f"正在搜索关键词: {query}")
            files = search_github_files(query, HEADERS)
            all_files.extend(files)
        
        # 搜索 GitHub Gists
        print("正在搜索 GitHub Gists...")
        gist_files = search_github_gists(HEADERS)
        all_files.extend(gist_files)
        
        # 搜索提交消息
        print("正在搜索提交消息...")
        commit_files = search_commit_messages(HEADERS)
        all_files.extend(commit_files)
        
        print(f"找到 {len(all_files)} 个潜在文件")
        
        all_nodes = []
        node_counter = 1  # 全局节点计数器
        for file_index, file_info in enumerate(all_files, 1):
            print(f"处理文件 {file_index}/{len(all_files)}: {file_info['repo']}/{file_info['path']}")
            content = get_file_content(file_info["file_url"], HEADERS)
            if content:
                nodes, node_counter = parse_snell_nodes(content, node_counter)
                all_nodes.extend(nodes)
            time.sleep(0.5)
        
        if all_nodes:
            print(f"共找到 {len(all_nodes)} 个 Snell 节点")
            config = generate_surge_config(all_nodes)
            save_config(config)
        else:
            print("未找到有效的 Snell 节点")
            
    except ValueError as ve:
        print(f"错误: {ve}")
    except Exception as e:
        print(f"发生未知错误: {e}")

if __name__ == "__main__":
    main()
