"""Package verified build outputs; does not access a serial port or flash a board."""
from pathlib import Path
import hashlib
import struct
import sys
import zipfile


def package(root: Path):
    release = root / "release"
    boot = (release / "bootloader.bin").read_bytes()
    app = (release / "firmware.bin").read_bytes()
    table = (release / "partitions.bin").read_bytes()
    if not boot or not app or boot[0] != 0xE9 or app[0] != 0xE9:
        raise ValueError("Expected ESP32 bootloader and application images")
    if len(boot) > 0x7000 or len(table) > 0x1000:
        raise ValueError("Bootloader/partition table overlaps the next region")
    found = False
    for pos in range(0, len(table), 32):
        entry = table[pos:pos + 32]
        if len(entry) != 32 or entry[:2] != b"\xaa\x50":
            break
        _, kind, subtype, offset, size, _, _ = struct.unpack("<HBBII16sI", entry)
        if kind == 0 and subtype == 0:
            if offset != 0x10000 or len(app) > size:
                raise ValueError("Application does not fit the factory partition")
            found = True
    if not found:
        raise ValueError("No factory application partition found")
    image = bytearray(b"\xff" * (0x10000 + len(app)))
    for offset, data in [(0x1000, boot), (0x8000, table), (0x10000, app)]:
        image[offset:offset + len(data)] = data
    (release / "wt32-link-factory.bin").write_bytes(image)
    (release / "WIREGUARD-LICENSE.txt").write_bytes((root / "components/wireguard/LICENSE").read_bytes())
    (release / "FLASH.txt").write_text(
        "WT32 Link / WT32-ETH01 / ESP32 / 4 MB flash\n\n"
        "FIRST INSTALL / FACTORY RESET (clears stored settings):\n"
        "python -m esptool --chip esp32 --port COM5 --baud 460800 write_flash 0x0 wt32-link-factory.bin\n\n"
        "UPDATE THIS WT32 LINK VERSION (preserves NVS settings):\n"
        "python -m esptool --chip esp32 --port COM5 --baud 460800 write_flash 0x1000 bootloader.bin 0x8000 partitions.bin 0x10000 firmware.bin\n\n"
        "Use esptool 4.5.1 syntax shown above; replace COM5 with the correct port.\n"
        "Never flash firmware.bin at 0x0: it is an application image for 0x10000.\n"
        "Connect UART at 3.3 V logic; enter download mode before flashing.\n"
        "After reboot: serial console 115200 gives SSID and admin password.\n"
        "Setup URL: http://192.168.4.1  Login: admin\n\n"
        "Build/test evidence is in README.md and BUILD-REPORT.md in the source project.\n"
        "Hardware VPN/NAT acceptance testing is still required.\n",
        encoding="utf-8",
    )
    source_files = [root / name for name in ("CMakeLists.txt", "platformio.ini", "partitions.csv", "sdkconfig.defaults", "README.md", "FUTURE-CHANGES.md", ".gitignore")]
    for folder in ("main", "components", "tests", "tools"):
        source_files.extend(p for p in (root / folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    if (root / "BUILD-REPORT.md").exists():
        source_files.append(root / "BUILD-REPORT.md")
    with zipfile.ZipFile(release / "wt32-link-source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_files):
            archive.write(path, path.relative_to(root))
    names = ["bootloader.bin", "partitions.bin", "firmware.bin", "wt32-link-factory.bin", "wt32-link-source.zip"]
    lines = [hashlib.sha256((release / name).read_bytes()).hexdigest() + "  " + name for name in names]
    (release / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"Packaged {len(app):,} byte app; {len(image):,} byte factory image in {release}")


if __name__ == "__main__":
    package(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
