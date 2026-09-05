from __future__ import annotations

import ipaddress
import os
import shlex
import socket
from typing import Any, Dict, List, Optional

try:
    import psutil
except Exception:
    psutil = None

from tools.ubuntu_commands import command_is_available


IP_USAGE = """Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }
       ip [ -force ] -batch filename
where  OBJECT := { address | addrlabel | amt | fou | help | ila | ioam | l2tp |
                   link | macsec | maddress | monitor | mptcp | mroute | mrule |
                   neighbor | netconf | netns | nexthop | ntable | ntbl | route |
                   rule | sr | tap | tcpmetrics | token | tunnel | tuntap | vrf |
                   xfrm }
       OPTIONS := { -V | -s | -d | -r | -h | -j | -p | -f { inet | inet6 |
                    bridge | mpls | link } | -4 | -6 | -M | -B | -0 |
                    -l { maximum-addr-flush-attempts } | -br | -o | -ts | -t |
                    -rcvbuf [size] | -netns name | -N | -all | -color }"""

_KNOWN_IP_OBJECT_NAMES = {
    "address", "addrlabel", "amt", "fou", "ila", "ioam", "l2tp", "link",
    "macsec", "maddress", "monitor", "mptcp", "mroute", "mrule", "neighbor",
    "netconf", "netns", "nexthop", "ntable", "ntbl", "route", "rule", "sr",
    "tap", "tcpmetrics", "token", "tunnel", "tuntap", "vrf", "xfrm",
}


def _prefix_from_netmask(netmask: str, fallback: int = 24) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except Exception:
        return fallback


def _configured_interfaces(system_log: Dict[str, Any]) -> List[Dict[str, Any]]:
    configured = ((system_log.get("network") or {}).get("interfaces") or {})
    if isinstance(configured, dict):
        configured = configured.get("items") or configured.get("details") or []
    if not isinstance(configured, list):
        return []
    return [dict(item) for item in configured if isinstance(item, dict) and item.get("name")]


def _discover_primary_interface() -> Dict[str, Any]:
    configured_ip = os.getenv("SIMULATED_IPV4", "").strip()
    configured_prefix = int(os.getenv("SIMULATED_IPV4_PREFIX", "24") or 24)
    configured_mac = os.getenv("SIMULATED_MAC", "02:42:ac:11:00:02").strip()
    if configured_ip:
        return {
            "name": os.getenv("SIMULATED_INTERFACE", "ens33"),
            "ipv4": configured_ip,
            "prefix": configured_prefix,
            "mac": configured_mac,
            "mtu": int(os.getenv("SIMULATED_MTU", "1500") or 1500),
            "state": "UP",
        }

    candidates: List[tuple[int, Dict[str, Any]]] = []
    if psutil is not None:
        try:
            stats = psutil.net_if_stats()
            link_family = getattr(psutil, "AF_LINK", object())
            for host_name, addresses in psutil.net_if_addrs().items():
                lowered = host_name.lower()
                if any(token in lowered for token in ("loopback", "bluetooth", "vmware", "virtual", "vethernet")):
                    continue
                ipv4 = None
                prefix = 24
                mac = "02:42:ac:11:00:02"
                for address in addresses:
                    if address.family == socket.AF_INET:
                        parsed = ipaddress.ip_address(address.address)
                        if parsed.is_loopback or parsed.is_link_local:
                            continue
                        ipv4 = address.address
                        prefix = _prefix_from_netmask(str(address.netmask or "255.255.255.0"))
                    elif address.family == link_family and address.address:
                        mac = str(address.address).replace("-", ":").lower()
                if not ipv4:
                    continue
                stat = stats.get(host_name)
                score = 100 if not ipaddress.ip_address(ipv4).is_private else 10
                if stat is not None and stat.isup:
                    score += 5
                if lowered in {"ethernet", "wi-fi", "wifi"}:
                    score += 20
                elif lowered.startswith("ethernet "):
                    score -= 5
                candidates.append((score, {
                    "name": "ens33",
                    "ipv4": ipv4,
                    "prefix": prefix,
                    "mac": mac,
                    "mtu": int(getattr(stat, "mtu", 1500) or 1500),
                    "state": "UP" if stat is None or stat.isup else "DOWN",
                }))
        except Exception:
            candidates = []
    if candidates:
        return max(candidates, key=lambda item: item[0])[1]
    return {
        "name": "ens33",
        "ipv4": "192.168.56.101",
        "prefix": 24,
        "mac": "02:42:ac:11:00:02",
        "mtu": 1500,
        "state": "UP",
    }


def _interfaces(system_log: Dict[str, Any]) -> List[Dict[str, Any]]:
    configured = _configured_interfaces(system_log)
    if configured:
        return configured
    primary = _discover_primary_interface()
    return [
        {
            "name": "lo",
            "ipv4": "127.0.0.1",
            "prefix": 8,
            "ipv6": "::1",
            "ipv6_prefix": 128,
            "mac": "00:00:00:00:00:00",
            "mtu": 65536,
            "state": "UNKNOWN",
            "loopback": True,
        },
        primary,
    ]


def _broadcast(ipv4: str, prefix: int) -> str:
    try:
        return str(ipaddress.ip_interface(f"{ipv4}/{prefix}").network.broadcast_address)
    except Exception:
        return "255.255.255.255"


def _render_link(interfaces: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for index, interface in enumerate(interfaces, 1):
        name = str(interface.get("name") or f"eth{index - 1}")
        loopback = bool(interface.get("loopback", name == "lo"))
        state = str(interface.get("state") or ("UNKNOWN" if loopback else "UP"))
        flags = "LOOPBACK,UP,LOWER_UP" if loopback else "BROADCAST,MULTICAST,UP,LOWER_UP"
        qdisc = "noqueue" if loopback else "fq_codel"
        lines.append(
            f"{index}: {name}: <{flags}> mtu {int(interface.get('mtu', 1500))} "
            f"qdisc {qdisc} state {state} mode DEFAULT group default qlen 1000"
        )
        if loopback:
            lines.append("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00")
        else:
            lines.append(f"    link/ether {interface.get('mac') or '02:42:ac:11:00:02'} brd ff:ff:ff:ff:ff:ff")
    return "\n".join(lines)


def _render_address(interfaces: List[Dict[str, Any]], family: Optional[int]) -> str:
    link_lines = _render_link(interfaces).splitlines()
    output: List[str] = []
    cursor = 0
    for interface in interfaces:
        output.extend(link_lines[cursor:cursor + 2])
        cursor += 2
        name = str(interface.get("name") or "eth0")
        loopback = bool(interface.get("loopback", name == "lo"))
        ipv4 = interface.get("ipv4")
        if family != 6 and ipv4:
            prefix = int(interface.get("prefix", 8 if loopback else 24))
            scope = "host" if loopback else "global dynamic noprefixroute"
            broadcast = "" if loopback else f" brd {_broadcast(str(ipv4), prefix)}"
            output.append(f"    inet {ipv4}/{prefix}{broadcast} scope {scope} {name}")
            output.append("       valid_lft forever preferred_lft forever")
        ipv6 = interface.get("ipv6")
        if family != 4 and ipv6:
            prefix6 = int(interface.get("ipv6_prefix", 128 if loopback else 64))
            scope6 = "host" if loopback else "link"
            output.append(f"    inet6 {ipv6}/{prefix6} scope {scope6}")
            output.append("       valid_lft forever preferred_lft forever")
    return "\n".join(output)


def _render_brief(interfaces: List[Dict[str, Any]], family: Optional[int], links_only: bool) -> str:
    lines: List[str] = []
    for interface in interfaces:
        name = str(interface.get("name") or "eth0")
        state = str(interface.get("state") or "UP")
        values: List[str] = []
        if not links_only and family != 6 and interface.get("ipv4"):
            values.append(f"{interface['ipv4']}/{int(interface.get('prefix', 24))}")
        if not links_only and family != 4 and interface.get("ipv6"):
            values.append(f"{interface['ipv6']}/{int(interface.get('ipv6_prefix', 64))}")
        lines.append(f"{name:<16} {state:<10} {' '.join(values)}".rstrip())
    return "\n".join(lines)


def _render_routes(system_log: Dict[str, Any], interfaces: List[Dict[str, Any]], family: Optional[int]) -> str:
    configured = (((system_log.get("network") or {}).get("routing") or {}).get("routes") or [])
    if isinstance(configured, list) and configured:
        return "\n".join(str(route) if not isinstance(route, dict) else str(route.get("text") or "") for route in configured)
    if family == 6:
        return ""
    primary = next((item for item in interfaces if not item.get("loopback") and item.get("ipv4")), None)
    if primary is None:
        return ""
    ipv4 = str(primary["ipv4"])
    prefix = int(primary.get("prefix", 24))
    network = ipaddress.ip_interface(f"{ipv4}/{prefix}").network
    name = str(primary.get("name") or "ens33")
    lines: List[str] = []
    gateway = os.getenv("SIMULATED_GATEWAY", "").strip()
    if gateway:
        lines.append(f"default via {gateway} dev {name} proto dhcp metric 100")
    lines.append(f"{network} dev {name} proto kernel scope link src {ipv4} metric 100")
    return "\n".join(lines)


def render_ip(command: str, system_log: Dict[str, Any]) -> Optional[str]:
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return f"ip: {exc}"
    if not tokens or tokens[0] != "ip":
        return None
    if command_is_available(command, system_log) is False:
        return None
    if len(tokens) == 1 or tokens[1] in {"-h", "--help", "help"}:
        return IP_USAGE

    family: Optional[int] = None
    brief = False
    position = 1
    while position < len(tokens) and tokens[position].startswith("-"):
        option = tokens[position]
        if option == "-4":
            family = 4
        elif option == "-6":
            family = 6
        elif option in {"-br", "-brief"}:
            brief = True
        elif option in {"-o", "-oneline", "-d", "-details", "-s", "-stats"}:
            pass
        else:
            return f'Option "{option}" is unknown, try "ip -help".'
        position += 1
    if position >= len(tokens):
        return IP_USAGE

    object_name = tokens[position]
    aliases = {
        "a": "address", "addr": "address", "address": "address",
        "l": "link", "link": "link",
        "r": "route", "route": "route",
        "n": "neighbor", "neigh": "neighbor", "neighbor": "neighbor",
    }
    canonical = aliases.get(object_name)
    if canonical is None:
        if object_name in _KNOWN_IP_OBJECT_NAMES:
            return None
        return f'Object "{object_name}" is unknown, try "ip help".'

    interfaces = _interfaces(system_log)
    if canonical == "address":
        return _render_brief(interfaces, family, links_only=False) if brief else _render_address(interfaces, family)
    if canonical == "link":
        return _render_brief(interfaces, family, links_only=True) if brief else _render_link(interfaces)
    if canonical == "route":
        return _render_routes(system_log, interfaces, family)
    return ""
