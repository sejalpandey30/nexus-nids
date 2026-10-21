"""
services/simulator.py — Safe local attack traffic simulator.

Why this exists:
  Real network attacks must never be generated against external hosts.
  This module creates synthetic flow records that mimic attack patterns 
  and submits them to the detection pipeline locally, allowing students 
  to demonstrate the NIDS without any real network activity.

How it connects to the NIDS architecture:
  The /api/simulate route calls functions from this module. Each 
  function returns a list of flow dicts which are then piped through 
  detect_flow(), providing realistic test coverage.
"""

import random
import time
from typing import List, Dict, Any, Optional

from backend.services.detection_service import detect_flow
from backend.utils.logger import get_logger

logger = get_logger("simulator")

# Fixed seed for reproducibility in single-scenario runs
_RNG = random.Random(42)


# ── Flow generators ───────────────────────────────────────────────────────────

def _normal_flow() -> Dict[str, float]:
    """Typical HTTP/HTTPS session: moderate duration, balanced bytes."""
    return {
        "duration":  round(_RNG.uniform(2, 25), 1),
        "src_bytes": round(_RNG.uniform(600, 2500), 0),
        "dst_bytes": round(_RNG.uniform(800, 4500), 0),
    }


def _port_scan_flow() -> Dict[str, float]:
    """Very short connection, almost no data — probing a port."""
    return {
        "duration":  round(_RNG.uniform(0.01, 0.9), 3),
        "src_bytes": round(_RNG.uniform(10, 90), 0),
        "dst_bytes": round(_RNG.uniform(0, 80), 0),
    }


def _dos_flow() -> Dict[str, float]:
    """Flood: source sends enormous traffic, destination barely responds."""
    return {
        "duration":  round(_RNG.uniform(1, 30), 2),
        "src_bytes": round(_RNG.uniform(500_000, 5_000_000), 0),
        "dst_bytes": round(_RNG.uniform(100, 5_000), 0),
    }


def _exfiltration_flow() -> Dict[str, float]:
    """Long session transferring a huge amount of data outbound."""
    return {
        "duration":  round(_RNG.uniform(61, 3600), 1),
        "src_bytes": round(_RNG.uniform(200, 2_000), 0),
        "dst_bytes": round(_RNG.uniform(10_000_001, 100_000_000), 0),
    }


def _data_theft_flow() -> Dict[str, float]:
    """Large download: dst_bytes >> src_bytes."""
    return {
        "duration":  round(_RNG.uniform(5, 120), 2),
        "src_bytes": round(_RNG.uniform(100, 1_000), 0),
        "dst_bytes": round(_RNG.uniform(50_000, 500_000), 0),
    }


_SCENARIO_MAP = {
    "normal":            _normal_flow,
    "port_scan":         _port_scan_flow,
    "dos":               _dos_flow,
    "data_exfiltration": _exfiltration_flow,
    "data_theft":        _data_theft_flow,
}

_PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSH"]
_SRC_IPS = ["192.168.1.105", "192.168.1.112", "10.0.0.45", "172.16.0.8", "192.168.0.22", "10.8.0.14"]
_DST_IPS = ["10.0.0.1", "172.217.16.206", "1.1.1.1", "142.250.190.46", "10.0.0.254", "192.168.1.1"]


def generate_single_packet_flow(anomaly_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate an individual simulated packet/flow record with network metadata
    (IPs, ports, protocol, checksum status) and run it through detection.
    """
    if anomaly_type and anomaly_type in _SCENARIO_MAP:
        generator = _SCENARIO_MAP[anomaly_type]
        scenario = anomaly_type
    else:
        # 65% normal, 35% random attack
        if random.random() < 0.65:
            generator = _normal_flow
            scenario = "normal"
        else:
            scenario = random.choice(["port_scan", "dos", "data_exfiltration", "data_theft"])
            generator = _SCENARIO_MAP[scenario]

    flow = generator()
    result = detect_flow(flow)

    src_port = random.choice([49152, 50214, 54321, 58210, 60124, 48991])
    if scenario == "port_scan":
        dst_port = random.choice([21, 22, 23, 25, 80, 443, 3389, 8080])
        protocol = "TCP"
    elif scenario == "dos":
        dst_port = random.choice([80, 443, 53])
        protocol = random.choice(["TCP", "UDP"])
    elif scenario == "data_exfiltration":
        dst_port = random.choice([443, 8443, 22])
        protocol = "HTTPS"
    elif scenario == "data_theft":
        dst_port = random.choice([80, 443, 3306, 5432])
        protocol = "HTTP"
    else:
        dst_port = random.choice([80, 443, 53])
        protocol = random.choice(["HTTPS", "HTTP", "DNS"])

    # Determine packet health / rule violation
    is_corrupted = (result.get("status") == "INTRUSION")
    flags = []
    if scenario == "port_scan":
        flags = ["SYN"]
    elif scenario == "dos":
        flags = ["SYN", "ACK", "FLOOD"]
    elif is_corrupted:
        flags = ["PSH", "ACK", "SUSPICIOUS"]
    else:
        flags = ["ACK"]

    packet_data = {
        **result,
        "packet_id": f"PKT-{random.randint(100000, 999999)}",
        "protocol": protocol,
        "src_ip": random.choice(_SRC_IPS),
        "dst_ip": random.choice(_DST_IPS),
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
        "is_corrupted": is_corrupted,
        "violation_rule": result.get("attack_type") if is_corrupted else None,
        "scenario": scenario,
        "packet_size": int(flow["src_bytes"] + flow["dst_bytes"]),
    }
    return packet_data



# ── Public functions ──────────────────────────────────────────────────────────

def simulate_scenario(scenario: str, count: int = 1) -> List[Dict[str, Any]]:
    """
    Generate *count* flows for *scenario* and run them through detection.

    Args:
        scenario: one of 'normal', 'port_scan', 'dos', 
                  'data_exfiltration', 'data_theft'.
        count:    number of flows to generate (default 1).

    Returns:
        List of detection result dicts.
    """
    if scenario not in _SCENARIO_MAP:
        raise ValueError(
            f"Unknown scenario '{scenario}'. "
            f"Choose from: {list(_SCENARIO_MAP.keys())}"
        )

    generator = _SCENARIO_MAP[scenario]
    results = []
    for _ in range(count):
        flow = generator()
        result = detect_flow(flow)
        result["scenario"] = scenario
        results.append(result)

    logger.info("Simulated %d '%s' flow(s).", count, scenario)
    return results


def run_full_simulation() -> List[Dict[str, Any]]:
    """
    Run a predefined sequence of all scenario types to demonstrate 
    the complete NIDS capability in one call.

    Returns:
        Aggregated list of detection results.
    """
    sequence = [
        ("normal",            3),
        ("port_scan",         2),
        ("dos",               2),
        ("data_exfiltration", 2),
        ("data_theft",        2),
        ("normal",            3),
    ]

    all_results: List[Dict[str, Any]] = []
    for scenario, count in sequence:
        all_results.extend(simulate_scenario(scenario, count))
        time.sleep(0.01)   # tiny pause so timestamps differ

    logger.info("Full simulation complete: %d flows processed.", len(all_results))
    return all_results


def list_scenarios() -> List[str]:
    """Return available scenario names."""
    return list(_SCENARIO_MAP.keys())
