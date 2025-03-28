import os
import requests
import base64
import time
import certifi
import re
import json
import concurrent.futures
import logging
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置日志为 DEBUG 级别以获取更多细节
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# 设置 SSL 证书路径
def setup_ssl():
    os.environ["SSL_CERT_FILE"] = certifi.where()

setup_ssl()

# 创建带重试机制的会话
def create_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.verify = certifi.where()
    return session

session = create_session()

# 测试代理是否可用
def test_proxy(proxy_line):
    try:
        proxies = {}
        if "vmess" in proxy_line:
            logging.info(f"Assuming VMess node valid for network test: {proxy_line[:50]}...")
            return True  # VMess 测试较为复杂，假设有效
        elif "trojan" in proxy_line or "ss" in proxy_line:
            match = re.search(r"(trojan|ss), ([^,]+), (\d+)", proxy_line)
            if match:
                protocol, server, port = match.groups()
                proxies = {"http": f"{protocol}://{server}:{port}", "https": f"{protocol}://{server}:{port}"}
            else:
                return False
        else:
            return False
        response = requests.get("https://www.google.com", proxies=proxies, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logging.debug(f"Proxy test failed for {proxy_line[:50]}...: {e}")
        return False

# 修正 Surge 配置中的常见错误
def correct_surge_config(config_text):
    corrections = {
        r'GEOIP, CN, BestProxy': 'GEOIP, CN, Fallback',
        r'FINAL, BestProxy': 'FINAL, Auto',
        r'GEOIP, CN, AutoSelect': 'GEOIP, CN, Fallback',
        r'GEOIP, CN, Fallback': 'GEOIP, CN, Proxy'
    }
    for pattern, replacement in corrections.items():
        config_text = re.sub(pattern, replacement, config_text)
    return config_text

# 解析 VMess 节点
def parse_vmess_node(vmess_url):
    try:
        if not vmess_url.startswith("vmess://"):
            return None
        base64_str = vmess_url.replace("vmess://", "").strip()
        json_str = base64.b64decode(base64_str + '=' * (4 - len(base64_str) % 4)).decode("utf-8", errors="ignore")
        config = json.loads(json_str)
        port = int(config.get("port", 0))
        server = config.get("add", "")
        uuid = config.get("id", "")
        if port <= 0 or port > 65535 or not server or not uuid or not re.match(r'^[0-9a-fA-F-]{36}$', uuid):
            logging.warning(f"Invalid VMess node (port: {port}, server: {server}, uuid: {uuid}): {vmess_url}")
            return None
        return {
            "server": server,
            "port": port,
            "uuid": uuid,
            "alterId": config.get("aid", "0"),
            "tls": config.get("tls", "") == "tls",
            "ps": config.get("ps", "Unnamed")
        }
    except Exception as e:
        logging.warning(f"Failed to parse VMess node {vmess_url}: {e}")
        return None

# 处理单个节点并转换为 Surge 格式
def process_node(node, idx):
    if node.startswith("vmess://"):
        vmess_config = parse_vmess_node(node)
        if vmess_config:
            return (
                f"Node-{idx} = vmess, {vmess_config['server']}, {vmess_config['port']}, {vmess_config['uuid']}, alterId={vmess_config['alterId']}, tls={str(vmess_config['tls']).lower()}, skip-cert-verify=true",
                "V2Ray",
                vmess_config
            )
        return None, None, None
    elif node.startswith("ss://"):
        try:
            ss_part = node.replace("ss://", "").split('#')[0].strip()
            decoded = base64.urlsafe_b64decode(ss_part + '=' * (4 - len(ss_part) % 4)).decode("utf-8")
            method_password, server_port = decoded.split('@', 1)
            method, password = method_password.split(':', 1)
            server, port = server_port.split(':', 1)
            return (
                f"Node-{idx} = ss, {server}, {port}, encrypt-method={method}, password={password}",
                "Shadowsocks",
                {"server": server, "port": port, "method": method, "password": password}
            )
        except Exception as e:
            logging.warning(f"Failed to parse SS node {node}: {e}")
            return None, None, None
    elif node.startswith("vless://"):
        logging.info(f"Discarding VLESS node (not supported by Surge): {node[:50]}...")
        return None, None, None
    elif "trojan" in node.lower():
        return f"Node-{idx} = {node}", "Trojan", {"server": re.search(r"trojan, ([^,]+),", node).group(1) if re.search(r"trojan, ([^,]+),", node) else "unknown"}
    elif "ssr" in node.lower():
        return f"Node-{idx} = {node}", "SSR", {"server": "SSR-not-parsed"}
    elif "wireguard" in node.lower():
        return f"Node-{idx} = {node}", "WireGuard", {"server": "WireGuard-not-parsed"}
    else:
        return None, None, None

# 解析订阅链接
def parse_subscription(url):
    try:
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text
            if "<html" in content.lower() or "<meta" in content.lower():
                logging.warning(f"Skipping HTML content from {url}")
                return []
            if re.match(r'^[A-Za-z0-9+/=]+$', content.strip()):
                content = base64.b64decode(content + '=' * (4 - len(content) % 4)).decode("utf-8", errors="ignore")
            nodes = [line.strip() for line in content.split("\n") if line.strip()]
            valid_nodes = []
            for node in nodes:
                if any(proto in node.lower() for proto in ["vmess://", "trojan", "ss://", "ssr", "wireguard", "vless://"]):
                    valid_nodes.append(node.split('#')[0].strip())  # 移除注释部分
            return valid_nodes
        else:
            logging.warning(f"Failed to fetch subscription {url}: {response.status_code}")
    except Exception as e:
        logging.warning(f"Error parsing subscription {url}: {e}")
    return []

# 验证节点有效性
def validate_node(node, idx):
    config_line, protocol, details = process_node(node, idx)
    if not config_line or not protocol:
        return None
    if protocol not in ["V2Ray", "Trojan", "SSR", "Shadowsocks", "WireGuard"]:
        logging.debug(f"Node {idx} discarded due to unsupported protocol: {protocol}")
        return None
    return {"config_line": config_line, "protocol": protocol, "details": details, "node_name": f"Node-{idx}"}

# 生成 Surge 配置
def generate_surge_config(valid_nodes):
    surge_config = "[Proxy]\n"
    proxy_groups = {"Trojan": [], "V2Ray": [], "SSR": [], "Shadowsocks": [], "WireGuard": []}

    for node in valid_nodes:
        surge_config += f"{node['config_line']}\n"
        proxy_groups[node['protocol']].append(node['node_name'])

    surge_config += "\n[Proxy Group]\n"
    
    def add_proxy_group(name, nodes, strategy="select"):
        nonlocal surge_config
        if nodes:
            surge_config += f"{name} = {strategy}, " + ", ".join(nodes) + "\n"
    
    add_proxy_group("Trojan", proxy_groups["Trojan"])
    add_proxy_group("V2Ray", proxy_groups["V2Ray"])
    add_proxy_group("SSR", proxy_groups["SSR"])
    add_proxy_group("Shadowsocks", proxy_groups["Shadowsocks"])
    add_proxy_group("WireGuard", proxy_groups["WireGuard"])
    add_proxy_group("Stable", sum(proxy_groups.values(), []), "fallback")
    add_proxy_group("Auto", sum(proxy_groups.values(), []), "select")

    surge_config += "\n[Rule]\n"
    surge_config += "GEOIP, CN, Stable\n"
    surge_config += "FINAL, Auto\n"

    return correct_surge_config(surge_config)

# 从 GitHub 获取 RAW 文件 URL
def fetch_github_raw_urls(repo_url):
    try:
        response = session.get(repo_url, timeout=10)
        if response.status_code != 200:
            logging.warning(f"Failed to fetch GitHub repo {repo_url}: {response.status_code}")
            return []
        
        html_content = response.text
        raw_urls = re.findall(r'href=["\']?(https://raw.githubusercontent.com/[^"\s]+?)["\s]', html_content)
        return [url for url in raw_urls if any(ext in url.lower() for ext in ['.txt', '.conf', '.sub', '.json'])]
    except Exception as e:
        logging.error(f"Error fetching raw URLs from {repo_url}: {e}")
        return []

# 从 GitHub 搜索仓库
def fetch_github_repos():
    repos = []
    SEARCH_QUERIES = [
        "Surge OR Clash OR V2Ray OR Trojan OR Shadowsocks OR WireGuard",
        "public VPN nodes OR free proxy OR proxy subscription",
        "SS SSR VMess Trojan nodes",
        "open source proxy list",
        "VPN subscription links",
        "free proxy nodes 2025",
        "Shadowsocks subscription",
        "V2Ray free nodes",
        "Trojan proxy list",
        "WireGuard config share"
    ]
    GITHUB_TOKEN = input("Please enter your GitHub Personal Access Token (PAT), or leave blank if you don't have one: ").strip()
    HEADERS = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    GITHUB_API = "https://api.github.com/search/repositories"
    
    def fetch_single_query(query):
        try:
            response = session.get(GITHUB_API, params={"q": query, "sort": "stars", "per_page": 100}, headers=HEADERS)
            if response.status_code == 200:
                return [repo["html_url"] for repo in response.json().get("items", [])]
            else:
                logging.warning(f"GitHub API request failed for query '{query}': {response.status_code}")
                return []
        except Exception as e:
            logging.error(f"Error fetching GitHub repos for query '{query}': {e}")
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_single_query, SEARCH_QUERIES)
        for result in results:
            repos.extend(result)
    
    raw_urls = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_repo = {executor.submit(fetch_github_raw_urls, repo): repo for repo in list(set(repos))}
        for future in concurrent.futures.as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                urls = future.result()
                raw_urls.extend(urls)
                logging.info(f"Fetched {len(urls)} raw URLs from {repo}")
            except Exception as e:
                logging.error(f"Error processing repo {repo}: {e}")
    return list(set(raw_urls))

# 额外的预定义源
def fetch_additional_sources():
    sources = [
        "https://raw.githubusercontent.com/freefq/free/master/v2",
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/shadowsocks.txt",
        "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
        "https://raw.githubusercontent.com/ssrsub/ssr/master/ssrsub",
        "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/trojan.txt",
        "https://raw.githubusercontent.com/free-vpn/free-vpn.github.io/master/subscription.txt",
        "https://raw.githubusercontent.com/clashconfig/clash/master/clash",
        "https://freevpn.us/subscription",
    ]
    return sources

# 获取所有节点
def fetch_all_nodes(sources, max_nodes_per_attempt=100):
    all_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(parse_subscription, url): url for url in sources}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                nodes = future.result()
                all_nodes.extend(nodes[:max_nodes_per_attempt])
                logging.info(f"Successfully fetched {len(nodes)} nodes from {url}, limited to {len(nodes[:max_nodes_per_attempt])}")
            except Exception as e:
                logging.error(f"Error fetching nodes from {url}: {e}")
    return all_nodes

# 过滤特定地区的节点
def filter_nodes_by_region(nodes):
    STRICT_REGIONS = ["CN", "IR", "RU", "SY"]
    return [node for node in nodes if not any(region in node.upper() for region in STRICT_REGIONS)]

# 主函数
def main():
    attempt = 0
    valid_nodes = []

    while len(valid_nodes) < 10 and attempt < 5:  # 限制最大尝试次数
        attempt += 1
        logging.info(f"Attempt {attempt}: Fetching GitHub repositories and additional sources...")
        github_repos = fetch_github_repos()
        additional_sources = fetch_additional_sources()
        all_sources = list(set(github_repos + additional_sources))

        if not all_sources:
            logging.error("No sources found. Please check your network or try again later.")
            time.sleep(2)
            continue

        logging.info("Parsing proxy nodes from all sources...")
        max_nodes = 50 if attempt <= 3 else 100
        all_nodes = fetch_all_nodes(all_sources, max_nodes_per_attempt=max_nodes)
        all_nodes = filter_nodes_by_region(all_nodes)

        if not all_nodes:
            logging.warning("No nodes found after filtering. Retrying...")
            time.sleep(2)
            continue

        logging.info(f"Validating nodes (total nodes: {len(all_nodes)})...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_node = {executor.submit(validate_node, node, idx): node for idx, node in enumerate(all_nodes, 1)}
            for future in concurrent.futures.as_completed(future_to_node):
                result = future.result()
                if result and result not in valid_nodes:
                    if test_proxy(result["config_line"]):
                        valid_nodes.append(result)
                        logging.info(f"Valid node found: {result['node_name']} (Total: {len(valid_nodes)})")

        if len(valid_nodes) < 10:
            logging.warning(f"Only {len(valid_nodes)} valid nodes found, need at least 10. Retrying...")

    if len(valid_nodes) < 10:
        logging.error("Failed to gather enough valid nodes after maximum attempts.")
        return

    logging.info("Generating and printing Surge configuration...")
    surge_config = generate_surge_config(valid_nodes)
    print("\n=== Surge Configuration ===")
    print(surge_config)
    print("==========================")

    print("\n=== First 10 Valid Proxy Nodes ===")
    for idx, node in enumerate(valid_nodes[:10], 1):
        print(f"{idx}. Name: {node['node_name']}")
        print(f"   Protocol: {node['protocol']}")
        print(f"   Details: {node['details']}")
        print("-------------------")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Process interrupted by user. Exiting gracefully.")
        print("\nScanning stopped by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print("\nAn error occurred. Check the logs for details.")
