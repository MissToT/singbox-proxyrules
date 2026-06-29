import os
import sys
import json
import urllib.request
import re
import tarfile
import gzip
import shutil

# ==================== 配置区 ====================
# Domain (Geosite)
URL_MISSTOT_CHINA_DOMAIN = "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/China.mrs"
URL_MISSTOT_PROXY_DOMAIN = "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/Proxy.mrs"
URL_QUIXOTIC_CN_DOMAIN = "https://v6.gh-proxy.org/github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/cn.mrs"
URL_QUIXOTIC_PROXY_DOMAIN = "https://v6.gh-proxy.org/github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/proxy.mrs"

# IP CIDR (GeoIP)
URL_QUIXOTIC_CN_IP = "https://v6.gh-proxy.org/github.com/QuixoticHeart/rule-set/raw/ruleset/meta/ipcidr/cn.mrs"
URL_QUIXOTIC_PROXY_IP = "https://raw.githubusercontent.com/QuixoticHeart/rule-set/ruleset/meta/ipcidr/proxy.mrs"


def get_latest_stable_asset_url(repo, pattern):
    # GitHub 的 /releases/latest 接口原生过滤掉了所有的 Pre-release (Alpha/Beta)，必定返回最新稳定版
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={'User-Agent': 'GitHub-Actions-Script'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            for asset in data.get('assets', []):
                if re.search(pattern, asset['name'], re.IGNORECASE):
                    return asset['browser_download_url']
    except Exception as e:
        print(f"获取 {repo} 最新稳定版本失败: {e}")
    return None

def setup_binaries():
    print("[-] 正在准备 sing-box 和 mihomo 最新稳定版编译内核...")
    
    # 准备 sing-box 最新稳定版
    sb_url = get_latest_stable_asset_url("SagerNet/sing-box", r"linux-amd64.*\.tar\.gz")
    if not sb_url:
        sb_url = "https://github.com/SagerNet/sing-box/releases/download/v1.18.0/sing-box-1.18.0-linux-amd64.tar.gz"
    urllib.request.urlretrieve(sb_url, "sing-box.tar.gz")
    with tarfile.open("sing-box.tar.gz", "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("/sing-box"):
                f = tar.extractfile(member)
                if f:
                    with open("sing-box", "wb") as out_f:
                        out_f.write(f.read())
    os.chmod("sing-box", 0o755)
    
    # 准备 mihomo 最新稳定版
    mihomo_url = get_latest_stable_asset_url("MetaCubeX/mihomo", r"linux-amd64.*\.gz")
    if not mihomo_url:
        mihomo_url = "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.3/mihomo-linux-amd64-v1.18.3.gz"
    urllib.request.urlretrieve(mihomo_url, "mihomo.gz")
    with gzip.open("mihomo.gz", "rb") as f_in:
        with open("mihomo", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.chmod("mihomo", 0o755)

def download_file(url, filename):
    print(f"[-] 下载规则源: {url} -> {filename}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            with open(filename, 'wb') as f:
                f.write(response.read())
    except Exception as e:
        print(f"下载失败 {url}: {e}")
        sys.exit(1)

def read_text_rules(filename):
    """读取文件并返回 Set 集合以实现自动全局去重"""
    if not os.path.exists(filename):
        return set()
    rules = set()
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                rules.add(line)
    return rules

def write_text_rules(rules_set, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        for rule in sorted(rules_set):
            f.write(f"{rule}\n")

def generate_mihomo_yaml(rules_set, filename):
    """生成 Mihomo 标准 YAML (Payload)"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule in sorted(rules_set):
            f.write(f"  - '{rule}'\n")

def generate_singbox_domain_json(rules_set, filename):
    """分离精确域名和泛域名，生成 Sing-box Domain JSON"""
    domains = []
    domain_suffixes = []
    
    for rule in sorted(rules_set):
        rule = rule.strip()
        if rule.startswith('+.'):
            domain_suffixes.append(rule[2:])
        elif rule.startswith('.'):
            domain_suffixes.append(rule[1:])
        else:
            domains.append(rule)
            
    rule_obj = {}
    if domains:
        rule_obj["domain"] = domains
    if domain_suffixes:
        rule_obj["domain_suffix"] = domain_suffixes
        
    sb_json = {
        "version": 2,
        "rules": [rule_obj] if rule_obj else []
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(sb_json, f, indent=2, ensure_ascii=False)

def generate_singbox_ip_json(rules_set, filename):
    """生成 Sing-box IPCIDR JSON"""
    ips = sorted(list(rules_set))
    sb_json = {
        "version": 2,
        "rules": [{"ip_cidr": ips}] if ips else []
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(sb_json, f, indent=2, ensure_ascii=False)

def main():
    setup_binaries()
    
    # ==================== 初始化分支目录树 ====================
    os.makedirs("mihomo_out/geo/geosite", exist_ok=True)
    os.makedirs("mihomo_out/geo/geoip", exist_ok=True)
    os.makedirs("singbox_out/geo/geosite", exist_ok=True)
    os.makedirs("singbox_out/geo/geoip", exist_ok=True)

    # ==================== 1. Domain (Geosite) 处理 ====================
    print("\n[+] 开始处理 Domain (Geosite) 规则...")
    download_file(URL_MISSTOT_CHINA_DOMAIN, "misstot_china_domain.mrs")
    download_file(URL_MISSTOT_PROXY_DOMAIN, "misstot_proxy_domain.mrs")
    download_file(URL_QUIXOTIC_CN_DOMAIN, "quixotic_china_domain.mrs")
    download_file(URL_QUIXOTIC_PROXY_DOMAIN, "quixotic_proxy_domain.mrs")

    os.system("./mihomo convert-ruleset domain mrs misstot_china_domain.mrs txt_mt_cn_domain.txt")
    os.system("./mihomo convert-ruleset domain mrs misstot_proxy_domain.mrs txt_mt_px_domain.txt")
    os.system("./mihomo convert-ruleset domain mrs quixotic_china_domain.mrs txt_qx_cn_domain.txt")
    os.system("./mihomo convert-ruleset domain mrs quixotic_proxy_domain.mrs txt_qx_px_domain.txt")

    # 去重合并
    china_domains = read_text_rules("txt_mt_cn_domain.txt") | read_text_rules("txt_qx_cn_domain.txt")
    proxy_domains = read_text_rules("txt_mt_px_domain.txt") | read_text_rules("txt_qx_px_domain.txt")

    # [China Domain] 导出 4 种格式
    generate_mihomo_yaml(china_domains, "mihomo_out/geo/geosite/china.yaml")
    generate_singbox_domain_json(china_domains, "singbox_out/geo/geosite/china.json")
    write_text_rules(china_domains, "merged_china_domain.txt")
    os.system("./mihomo convert-ruleset domain text merged_china_domain.txt mihomo_out/geo/geosite/china.mrs")
    os.system("./sing-box rule-set compile --output singbox_out/geo/geosite/china.srs singbox_out/geo/geosite/china.json")

    # [Proxy Domain] 导出 4 种格式
    generate_mihomo_yaml(proxy_domains, "mihomo_out/geo/geosite/proxy.yaml")
    generate_singbox_domain_json(proxy_domains, "singbox_out/geo/geosite/proxy.json")
    write_text_rules(proxy_domains, "merged_proxy_domain.txt")
    os.system("./mihomo convert-ruleset domain text merged_proxy_domain.txt mihomo_out/geo/geosite/proxy.mrs")
    os.system("./sing-box rule-set compile --output singbox_out/geo/geosite/proxy.srs singbox_out/geo/geosite/proxy.json")


    # ==================== 2. IP CIDR (GeoIP) 处理 ====================
    print("\n[+] 开始处理 IP CIDR (GeoIP) 规则...")
    download_file(URL_QUIXOTIC_CN_IP, "quixotic_china_ip.mrs")
    download_file(URL_QUIXOTIC_PROXY_IP, "quixotic_proxy_ip.mrs")

    # 注意：IP规则解编必须使用 ipcidr 参数
    os.system("./mihomo convert-ruleset ipcidr mrs quixotic_china_ip.mrs txt_qx_cn_ip.txt")
    os.system("./mihomo convert-ruleset ipcidr mrs quixotic_proxy_ip.mrs txt_qx_px_ip.txt")

    # 读取并自动去重
    china_ips = read_text_rules("txt_qx_cn_ip.txt")
    proxy_ips = read_text_rules("txt_qx_px_ip.txt")

    # [China IP] 导出 4 种格式
    generate_mihomo_yaml(china_ips, "mihomo_out/geo/geoip/china.yaml")
    generate_singbox_ip_json(china_ips, "singbox_out/geo/geoip/china.json")
    write_text_rules(china_ips, "merged_china_ip.txt")
    os.system("./mihomo convert-ruleset ipcidr text merged_china_ip.txt mihomo_out/geo/geoip/china.mrs")
    os.system("./sing-box rule-set compile --output singbox_out/geo/geoip/china.srs singbox_out/geo/geoip/china.json")

    # [Proxy IP] 导出 4 种格式
    generate_mihomo_yaml(proxy_ips, "mihomo_out/geo/geoip/proxy.yaml")
    generate_singbox_ip_json(proxy_ips, "singbox_out/geo/geoip/proxy.json")
    write_text_rules(proxy_ips, "merged_proxy_ip.txt")
    os.system("./mihomo convert-ruleset ipcidr text merged_proxy_ip.txt mihomo_out/geo/geoip/proxy.mrs")
    os.system("./sing-box rule-set compile --output singbox_out/geo/geoip/proxy.srs singbox_out/geo/geoip/proxy.json")

    print("\n[√] 所有的去重合并、保留明文（YAML/JSON）以及双核心二进制（MRS/SRS）编译均已执行完毕！")

if __name__ == "__main__":
    main()