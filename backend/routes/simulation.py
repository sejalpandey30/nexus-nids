"""
routes/simulation.py — /api/simulate endpoint.

Why this exists:
  The attack simulator is an educational tool that lets the dashboard 
  trigger synthetic attack flows without real network activity. It is 
  a separate route so it can be disabled in production environments.
"""

from flask import Blueprint, request, jsonify

from backend.services.simulator import (
    simulate_scenario,
    run_full_simulation,
    list_scenarios,
    generate_single_packet_flow,
)
from backend.models.model_manager import get_alert_db
from backend.utils.logger import get_logger

logger = get_logger("routes.simulation")

simulation_bp = Blueprint("simulation", __name__)


@simulation_bp.route("/api/simulate", methods=["POST"])
def simulate():
    """
    POST /api/simulate
    Runs a traffic simulation scenario.

    Body:
        { "scenario": "port_scan", "count": 3 }
        or
        { "scenario": "full" }
    """
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "normal")
    count    = int(data.get("count", 1))

    try:
        if scenario == "full":
            results = run_full_simulation()
        else:
            results = simulate_scenario(scenario, count)

        # Log all simulated flows for statistics
        db = get_alert_db()
        for r in results:
            db.log_flow(r)

        return jsonify({
            "scenario": scenario,
            "count":    len(results),
            "results":  results,
        }), 200

    except ValueError as exc:
        return jsonify({"error": str(exc), "available_scenarios": list_scenarios()}), 400
    except Exception as exc:
        logger.exception("Simulation error: %s", exc)
        return jsonify({"error": "Simulation failed.", "detail": str(exc)}), 500


@simulation_bp.route("/api/simulate/scenarios", methods=["GET"])
def scenarios():
    """GET /api/simulate/scenarios — list available scenario names."""
    return jsonify({"scenarios": list_scenarios()}), 200


@simulation_bp.route("/api/simulate/packet", methods=["GET", "POST"])
def simulate_packet():
    """
    GET/POST /api/simulate/packet
    Generates a single live packet flow, evaluates it against rule & ML engine,
    and returns rich packet-level telemetry (IPs, ports, flags, rule violation, corruption status).
    Optional query/body param: 'scenario' (normal, port_scan, dos, data_exfiltration, data_theft).
    """
    scenario = None
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        scenario = data.get("scenario")
    else:
        scenario = request.args.get("scenario")

    try:
        packet = generate_single_packet_flow(anomaly_type=scenario)
        # Log to database for live statistics updates
        get_alert_db().log_flow(packet)
        return jsonify(packet), 200
    except Exception as exc:
        logger.exception("Packet simulation error: %s", exc)
        return jsonify({"error": "Failed to generate packet", "detail": str(exc)}), 500


@simulation_bp.route("/api/simulate/stream", methods=["GET"])
def simulate_stream():
    """
    GET /api/simulate/stream
    Server-Sent Events (SSE) endpoint providing a real-time stream of network packets.
    Clients can connect and continuously receive packet flows every N milliseconds.
    """
    import json
    import time
    from flask import Response

    rate = float(request.args.get("interval", 1.0))
    scenario = request.args.get("scenario")
    rate = max(0.2, min(5.0, rate))  # Clamp interval between 0.2s and 5.0s

    def event_stream():
        db = get_alert_db()
        while True:
            try:
                pkt = generate_single_packet_flow(anomaly_type=scenario)
                db.log_flow(pkt)
                yield f"data: {json.dumps(pkt)}\n\n"
                time.sleep(rate)
            except GeneratorExit:
                break
            except Exception as e:
                logger.error("SSE stream error: %s", e)
                break

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

