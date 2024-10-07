#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12,<4"
# dependencies = [
#     "pyyaml>=6.0.2,<7",
#     "requests>=2.32.3,<3",
# ]
# ///
import argparse
import base64
import logging
import re
import sys
from collections.abc import Iterable
from urllib.parse import urlparse, unquote

import requests
import yaml


def parse_gfwlist(b64content: bytes, tlds: set[str]) -> set[str]:
    content = base64.b64decode(b64content).decode("utf-8")

    domains: set[str] = set()
    for line in content.splitlines(keepends=False):
        rule = line

        if not rule:
            continue
        if rule.startswith("!"):
            # comment
            continue
        if rule.startswith("["):
            # [AutoProxy x.x.x]
            continue
        if rule.startswith("@"):
            # white list
            continue
        if rule.startswith("/"):
            # regex
            if "*" in rule:
                continue
            if "[" in rule:
                continue
            if "|" in rule:
                continue
            if "(" in rule:
                continue
            rule = rule.strip("/").replace(r"\/", "/").replace(r"\.", ".")
            rule = re.sub(r".\?", "", rule)

        rule = unquote(rule, "utf-8")
        if ".*" in rule:
            continue

        rule = re.sub("(?<=\\w)\\*(?=\\w)", "/", rule)
        rule = rule.replace("*", "")
        rule = rule.lstrip("|")
        rule = rule.removeprefix("http://")
        rule = rule.removeprefix("https://")
        rule = rule.lstrip(".")

        try:
            url = "https://" + rule
            domain = urlparse(url).hostname
            # convert to punycode
            domain = domain.encode("idna").decode("utf-8")
            domain_sld = get_domain_sld(domain, tlds)
            domains.add(domain_sld)
        except Exception as e:
            logging.error("Parse line: %s error! %s", line, e)

    return domains


def parse_tlds(content: str) -> set[str]:
    tlds: set[str] = set()
    for line in content.splitlines(False):
        if not line:
            continue
        if line.startswith("//"):
            # ignore comment
            continue
        tld = line.encode("idna").decode("utf-8")
        tlds.add(tld)
    return tlds


def get_domain_sld(domain: str, tlds: set[str]) -> str:
    # get second level domain from a domain, if domain is not valid, raise
    domain_parts = domain.split(".")
    domain_len = len(domain_parts)
    for start in range(0, domain_len):
        root_domain = ".".join(domain_parts[start + 1 :])
        if root_domain in tlds:
            return f"{domain_parts[start]}.{root_domain}"
    raise ValueError(f"{domain} not found in tlds")


def first_or_none[T](d: Iterable[T]) -> T | None:
    try:
        return next(iter(d))
    except StopIteration:
        return None


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--blacklist",
        help="Custom black list",
        default="blacklist.txt",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Clash config file path",
        default="StashConfig.yaml",
    )
    parser.add_argument(
        "--gfwlist-url",
        help="GFWList URL",
        default="https://hub.gitmirror.com/https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
    )
    parser.add_argument(
        "--tlds-url",
        help="TLDs URL",
        default="https://publicsuffix.org/list/public_suffix_list.dat",
    )
    args = parser.parse_args()

    logging.info(f"Downloading tlds from {args.tlds_url}")
    tlds_resp = requests.get(args.tlds_url, timeout=10, allow_redirects=True)
    tlds_resp.raise_for_status()
    logging.info("tlds_resp: %s", tlds_resp)
    tlds = parse_tlds(tlds_resp.content.decode("utf-8"))

    logging.info(f"Downloading gfwlist from {args.gfwlist_url}")
    gfwlist_resp = requests.get(args.gfwlist_url, timeout=10, allow_redirects=True)
    tlds_resp.raise_for_status()
    logging.info("gfwlist_resp: %s", gfwlist_resp)
    gfwlist = parse_gfwlist(gfwlist_resp.content, tlds)

    with open(args.blacklist, "r") as fp:
        custom_blacklist = fp.read().splitlines()

    blacklist = {*gfwlist, *custom_blacklist}

    with open(args.config, "r") as fp:
        config = yaml.safe_load(fp)

    dns_config = config.get("dns") or {}
    nameserver_policy = dns_config.get("nameserver-policy") or {}
    trusted_nameserver = (
        first_or_none(nameserver_policy.values())
        or "https://cloudflare-dns.com/dns-query"
    )

    nameserver_policy = {
        f"+.{domain}": trusted_nameserver for domain in sorted(blacklist)
    }
    if not nameserver_policy:
        nameserver_policy["do-not-remove"] = trusted_nameserver
    dns_config["nameserver-policy"] = nameserver_policy
    config["dns"] = dns_config

    with open(args.config, "w", newline="") as fp:
        yaml.safe_dump(config, fp, allow_unicode=True, sort_keys=False)


if __name__ == "__main__":
    sys.exit(main())
