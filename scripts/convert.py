import json
import os
import re
import sys
import urllib.request

# ============================================================
# 配置区域：name 为输出文件名，subfolder 为输出子目录
# ============================================================
SOURCES = [
    {
        "name": "proxy",
        "subfolder": "domain",
        "url": "https://raw.githubusercontent.com/QuixoticHeart/rule-set/ruleset/meta/domain/proxy.list",
    },
    {
        "name": "proxy",
        "subfolder": "ipcidr",
        "url": "https://raw.githubusercontent.com/QuixoticHeart/rule-set/ruleset/meta/ipcidr/proxy.list",
    },
]

OUTPUT_DIR = "dist"


def download_source(url: str) -> str:
    """从 URL 下载规则文件内容"""
    req = urllib.request.Request(url, headers={"User-Agent": "singbox-ruleset-updater/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def convert_to_singbox(content: str, source_name: str) -> dict | None:
    """将 mihomo 规则列表转换为 sing-box rules JSON"""

    rule_collections = {
        "domain":            set(),
        "domain_suffix":     set(),
        "domain_keyword":    set(),
        "domain_regex":      set(),
        "ip_cidr":           set(),
        "source_ip_cidr":    set(),
        "port":              set(),
        "port_range":        set(),
        "source_port":       set(),
        "source_port_range": set(),
        "process_name":      set(),
        "process_path":      set(),
    }

    ip_re = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}(/\d+)?$"
        r"|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d+)?$"
    )

    for raw_line in content.splitlines():
        line = raw_line.split("#")[0].split("//")[0].strip()

        if not line or line.lower() == "payload:":
            continue

        val_match = re.search(r'^(?:-\s+)?["\']?(.*?)["\']?$', line)
        if not val_match:
            continue
        val = val_match.group(1).strip()

        if not val or val.lower() == "payload:":
            continue

        # ── A. Classical 格式 (TYPE,VALUE[,no-resolve]) ──────────────────
        if "," in val:
            parts = [p.strip() for p in val.split(",")]
            if len(parts) >= 2:
                rule_type  = parts[0].upper()
                rule_value = parts[1].strip("'\"")

                simple_map = {
                    "DOMAIN":         "domain",
                    "DOMAIN-SUFFIX":  "domain_suffix",
                    "DOMAIN-KEYWORD": "domain_keyword",
                    "DOMAIN-REGEX":   "domain_regex",
                    "SRC-IP-CIDR":    "source_ip_cidr",
                    "PROCESS-NAME":   "process_name",
                    "PROCESS-PATH":   "process_path",
                }

                if rule_type in simple_map:
                    rule_collections[simple_map[rule_type]].add(rule_value)
                elif rule_type in ("IP-CIDR", "IP-CIDR6"):
                    rule_collections["ip_cidr"].add(rule_value)
                elif rule_type == "DST-PORT":
                    if "-" in rule_value:
                        rule_collections["port_range"].add(rule_value)
                    else:
                        try:
                            rule_collections["port"].add(int(rule_value))
                        except ValueError:
                            pass
                elif rule_type == "SRC-PORT":
                    if "-" in rule_value:
                        rule_collections["source_port_range"].add(rule_value)
                    else:
                        try:
                            rule_collections["source_port"].add(int(rule_value))
                        except ValueError:
                            pass
            continue

        # ── B. 纯文本格式 (domain / ipcidr 类型文件) ─────────────────────
        if ip_re.match(val):
            rule_collections["ip_cidr"].add(val)
        elif val == "*":
            rule_collections["domain_regex"].add(r"^[^.]+$")
        elif val.startswith("*.") and val.count("*") == 1:
            core = val[2:].replace(".", r"\.")
            rule_collections["domain_regex"].add(rf"^[^.]+\.{core}$")
        elif val.startswith("*") and val.endswith("*") and len(val) > 2:
            rule_collections["domain_keyword"].add(val.strip("*"))
        elif val.startswith("+."):
            rule_collections["domain_suffix"].add(val[2:])
        elif val.startswith("."):
            rule_collections["domain_suffix"].add(val[1:])
        else:
            rule_collections["domain"].add(val)

    # ── 组装 rules 数组 ───────────────────────────────────────────────────
    rules_array = []

    group_network = {}
    for key in ["domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"]:
        if rule_collections[key]:
            group_network[key] = sorted(rule_collections[key])
    if group_network:
        rules_array.append(group_network)

    if rule_collections["source_ip_cidr"]:
        rules_array.append({"source_ip_cidr": sorted(rule_collections["source_ip_cidr"])})

    group_port = {}
    for key in ["port", "port_range"]:
        if rule_collections[key]:
            group_port[key] = sorted(rule_collections[key])
    if group_port:
        rules_array.append(group_port)

    group_src_port = {}
    for key in ["source_port", "source_port_range"]:
        if rule_collections[key]:
            group_src_port[key] = sorted(rule_collections[key])
    if group_src_port:
        rules_array.append(group_src_port)

    group_process = {}
    for key in ["process_name", "process_path"]:
        if rule_collections[key]:
            group_process[key] = sorted(rule_collections[key])
    if group_process:
        rules_array.append(group_process)

    if not rules_array:
        print(f"⚠️  [{source_name}] 未提取到有效规则，已跳过。")
        return None

    return {"version": 2, "rules": rules_array}


def count_rules(data: dict) -> int:
    return sum(
        len(v)
        for rule_block in data["rules"]
        for v in rule_block.values()
        if isinstance(v, list)
    )


def main():
    ok, fail = 0, 0

    for source in SOURCES:
        name      = source["name"]
        subfolder = source["subfolder"]
        url       = source["url"]
        out_dir   = os.path.join(OUTPUT_DIR, subfolder)

        os.makedirs(out_dir, exist_ok=True)

        print(f"\n{'─'*50}")
        print(f"📥  下载中: {subfolder}/{name}")
        print(f"    {url}")

        try:
            content = download_source(url)
            print(f"    大小: {len(content):,} 字节, {content.count(chr(10)):,} 行")
        except Exception as exc:
            print(f"❌  下载失败: {exc}")
            fail += 1
            continue

        print(f"🔄  转换中: {subfolder}/{name}")
        result = convert_to_singbox(content, f"{subfolder}/{name}")

        if result:
            out_path = os.path.join(out_dir, f"{name}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"✅  已生成: {out_path}  ({count_rules(result):,} 条规则)")
            ok += 1
        else:
            fail += 1

    print(f"\n{'='*50}")
    print(f"完成 — 成功: {ok}  失败: {fail}")
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
