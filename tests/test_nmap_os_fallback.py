from pathlib import Path

from scanfuse.parsers.nmap import NmapParser


def test_nmap_keeps_os_name_without_accuracy(tmp_path: Path) -> None:
    source = tmp_path / "unscored-os.xml"
    source.write_text('''<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4" />
      <ports><port protocol="tcp" portid="80"><state state="open" /></port></ports>
      <os><osmatch name="Linux" /></os>
    </host></nmaprun>''', encoding="utf-8")
    findings = NmapParser().parse(str(source))
    assert findings[0].hosts[0].os == "Linux"
