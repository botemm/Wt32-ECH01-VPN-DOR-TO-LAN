"""Read-only UI preview. All values are fixtures, not live hardware telemetry."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1] / "main" / "web"
CONFIG = dict(mode="auto", ssid="Workshop", enabled=True, address="10.7.0.2",
              remote_cidr="10.7.0.0/24", endpoint="vpn.example.com", port=51820,
              lan_cidr="", admin_user="admin", ap_ssid="", ap_timeout=300,
              keepalive=25, mtu=1280, public_key="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
              device_public_key="AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
              has_private_key=True, has_wifi_password=True, has_psk=False, has_ap_password=True,
              setup_ssid="WT32-Link-DEMO")
STATUS = dict(uplink="Ethernet", ip="192.168.10.50", lan="192.168.10.0/24",
              state="ДЕМОНСТРАЦІЯ ІНТЕРФЕЙСУ · Дані умовні", ethernet=True, wifi=True,
              tunnel=True, clock_ready=True, ap=True, ap_remaining=228, ap_clients=0, rssi=-54, rx_bytes=1857824,
              tx_bytes=495322, dropped=0, last_rx_age=2, uptime=3720, heap=114520)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        fixture = {"/api/config": CONFIG, "/api/status": STATUS,
                   "/api/scan": dict(running=False, progress=0, total=0, error="", hosts=[])}.get(self.path)
        if fixture is not None:
            data = json.dumps(fixture, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            super().do_GET()

    def do_POST(self):
        self.send_error(403, "Read-only preview; no device is connected")

if __name__ == "__main__":
    print("Read-only UI preview: http://127.0.0.1:8765", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
