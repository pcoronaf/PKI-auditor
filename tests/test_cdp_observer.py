"""Pruebas del sensor CDP sin navegador: se le entregan eventos como los que
emitiria Chromium."""

from __future__ import annotations

from types import SimpleNamespace

from firmascope.audit_core.events import EventType
from firmascope.network_analyzer.cdp_observer import NetworkObserver

from conftest import T0, make_config


class FakeStore:
    def add_request(self, record) -> None:
        pass

    def update_request(self, request_id, **fields) -> None:
        pass

    def add_evidence(self, *args, **kwargs):
        return {"path": ""}


def observer():
    emitted = []
    obs = NetworkObserver("s", FakeStore(), make_config(), emitted.append)
    return obs, emitted


def request_will_be_sent(request_id: str, wall: float, monotonic: float) -> dict:
    return {"requestId": request_id, "wallTime": wall, "timestamp": monotonic, "type": "XHR",
            "request": {"url": "https://sitio.example/api", "method": "GET", "headers": {}}}


def test_las_respuestas_se_fechan_con_el_reloj_de_pared():
    """CDP fecha las respuestas con su reloj monotono (segundos desde el
    arranque); sin convertirlas, el expediente las situaba en 1970."""
    obs, emitted = observer()
    obs._dispatch("Network.requestWillBeSent", request_will_be_sent("1", T0, 1000.0), "main")
    obs._dispatch("Network.responseReceived",
                  {"requestId": "1", "timestamp": 1002.5,
                   "response": {"url": "https://sitio.example/api", "status": 200}}, "main")
    obs._dispatch("Network.loadingFailed",
                  {"requestId": "1", "timestamp": 1003.0, "errorText": "net::ERR_FAILED"}, "main")
    response = next(e for e in emitted if e.type is EventType.NETWORK_RESPONSE)
    failed = next(e for e in emitted if e.type is EventType.NETWORK_FAILED)
    assert response.timestamp == T0 + 2.5
    assert failed.timestamp == T0 + 3.0


def test_sin_referencia_se_usa_la_hora_actual(monkeypatch):
    import firmascope.network_analyzer.cdp_observer as mod
    monkeypatch.setattr(mod, "now", lambda: T0 + 42.0)
    obs, emitted = observer()
    obs._dispatch("Network.responseReceived",
                  {"requestId": "x", "timestamp": 55.0, "response": {"url": "u", "status": 200}},
                  "main")
    assert emitted[0].timestamp == T0 + 42.0
