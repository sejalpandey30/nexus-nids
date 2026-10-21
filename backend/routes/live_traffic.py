"""
live_traffic.py — REST and SSE endpoints for physical NIC packet sniffing.

Allows frontend to check raw socket permissions, select an interface,
start/stop physical packet capturing, and receive real-time SSE telemetry
for physical packets sent and received by the host machine.
"""

import json
import time
import queue
from flask import Blueprint, jsonify, request, Response

from backend.services.live_sniffer import (
    get_live_sniffer,
    get_local_interfaces,
    check_raw_socket_permission,
)
from backend.utils.logger import get_logger

logger = get_logger("live_traffic_routes")

live_traffic_bp = Blueprint("live_traffic", __name__, url_prefix="/api/live")


@live_traffic_bp.route("/status", methods=["GET"])
def live_status():
    """
    Check if Python has native raw socket permissions on Windows,
    and return available network interfaces and sniffer status.
    """
    sniffer = get_live_sniffer()
    interfaces = get_local_interfaces()
    target_ip = request.args.get("ip") or (sniffer.active_ip if sniffer.is_running else None)
    
    can_capture, is_raw, mode_label, active_ip = check_raw_socket_permission(target_ip)

    return jsonify({
        "status": "online",
        "is_running": sniffer.is_running,
        "active_ip": sniffer.active_ip or active_ip,
        "can_capture": can_capture,
        "is_raw": is_raw,
        "mode_label": mode_label,
        "error_message": None,
        "interfaces": interfaces,
        "total_packets": sniffer.total_packets_sniffed,
        "total_flows": sniffer.total_flows_evaluated,
    }), 200


@live_traffic_bp.route("/start", methods=["POST"])
def live_start():
    """Start capturing physical packets on the designated or default interface."""
    data = request.get_json(silent=True) or {}
    target_ip = data.get("ip")

    sniffer = get_live_sniffer()
    success, message = sniffer.start(target_ip)

    if not success:
        return jsonify({
            "status": "error",
            "message": message,
            "can_capture": False,
        }), 400

    return jsonify({
        "status": "started",
        "message": message,
        "active_ip": sniffer.active_ip,
    }), 200


@live_traffic_bp.route("/stop", methods=["POST"])
def live_stop():
    """Stop live packet capture."""
    sniffer = get_live_sniffer()
    success, message = sniffer.stop()
    return jsonify({
        "status": "stopped",
        "message": message,
    }), 200


@live_traffic_bp.route("/stream", methods=["GET"])
def live_stream():
    """
    Server-Sent Events endpoint streaming real physical packets and reassembled flows.
    """
    sniffer = get_live_sniffer()

    # If sniffer is not currently running, attempt to start it
    if not sniffer.is_running:
        req_ip = request.args.get("ip")
        ok, msg = sniffer.start(req_ip)
        if not ok:
            logger.warning("Could not auto-start live sniffer: %s", msg)

    q = sniffer.subscribe()

    def event_generator():
        try:
            # Yield initial connection confirmation
            init_event = {
                "type": "connection",
                "message": f"Connected to Physical NIC stream ({sniffer.active_ip or 'auto'})",
                "timestamp": time.time(),
            }
            yield f"data: {json.dumps(init_event)}\n\n"

            while True:
                try:
                    # Wait up to 1 second for a packet flow
                    packet = q.get(timeout=1.0)
                    yield f"data: {json.dumps(packet)}\n\n"
                except queue.Empty:
                    # Send periodic keep-alive comment
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            pass
        finally:
            sniffer.unsubscribe(q)

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
