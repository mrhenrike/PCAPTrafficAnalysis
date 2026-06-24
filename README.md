# PCAPTrafficAnalysis

[![Author](https://img.shields.io/badge/author-mrhenrike-black?logo=github)](https://github.com/mrhenrike)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/mrhenrike/PCAPTrafficAnalysis/blob/main/LICENSE)
[![Purpose](https://img.shields.io/badge/purpose-OT%20%2F%20ICS%20%2F%20Lab-red)](https://github.com/mrhenrike/PCAPTrafficAnalysis)

Network packet captures collected in **laboratory and controlled environments** for educational use in OT/ICS security research, training, and tool development.

> **Author:** Andre Henrique ([@mrhenrike](https://github.com/mrhenrike)) — LinkedIn/X: @mrhenrike

---

## Contents

| Category | Files | Description |
|----------|-------|-------------|
| **Lab field tests** | `ColetaTF01.pcap` – `ColetaTF09.pcap` | Sequential lab captures: Wi-Fi, TCP, SMTP, DNP3, Modbus, WPA2 handshakes |
| **Modbus TCP** | `ICS-Modbus-001.pcap`, `ICS-Modbus-002.pcap`, `ICS-Modbus-003.pcap` | Modbus function codes, read/write coils and registers |
| **DNP3** | `ICS-DNP3-001.pcap` – `ICS-DNP3-004.pcap` | DNP3 over TCP — application layer objects and timing |
| **S7comm** | `ICS-S7-001.pcapng`, `ICS-S7-002.pcap` | Siemens S7/TIA communication over TCP port 102 |
| **PROFINET** | `ICS-Profinet-001.pcap` – `ICS-Profinet-003.pcap` | LLDP discovery, PN-IO cyclic data, DCERPC alarms |
| **EtherCAT** | `ICS-Ethercat-001.pcap` | EtherCAT master/slave frames and PDO exchange |
| **OT malware** | `ICS-OT-Malware-001.pcap` | HTTP payload retrieval in OT network context |
| **OT network** | `ICS-OT-Network-001.pcap` | Mixed OT traffic: IEC 60870-5-104, RTSP, SNMP, SMB |

**25 capture files** total — `.pcap` and `.pcapng` in repository root.

---

## Usage

Open `.pcap` / `.pcapng` files with [Wireshark](https://www.wireshark.org/) or process with `tshark`:

```bash
# Protocol hierarchy
tshark -r ICS-Modbus-001.pcap -q -z io,phs

# Modbus function codes
tshark -r ICS-Modbus-001.pcap -Y "modbus" -T fields -e frame.number -e ip.src -e modbus.func_code

# TCP conversation list
tshark -r ColetaTF02.pcap -q -z conv,tcp

# Follow a TCP stream (ASCII)
tshark -r ColetaTF03.pcap -q -z follow,tcp,ascii,0

# All lab captures — quick overview
for f in ColetaTF*.pcap ColetaTF*.pcapng; do echo "=== $f ==="; tshark -r "$f" -q -z io,phs; done
```

---

## License

This repository is licensed under the **MIT License** — see [LICENSE](LICENSE).

---

<!-- LEGAL-NOTICE-UG-MRH -->

## Aviso legal / Legal Notice

- **Uso** — Apenas para educação, pesquisa e ambientes **autorizados**. Não utilize capturas ou ferramentas contra redes ou sistemas sem permissão explícita.
- **Sem garantia** — Conteúdo **AS IS**; sem garantias expressas ou implícitas de qualquer tipo.
- **Responsabilidade** — O autor **não se responsabiliza** por uso indevido, danos ou violação de leis ou políticas; **uso por sua conta e risco**.
- **Atribuição** — Mantenha os créditos ao repositório original. **Pull requests** e **issues** são bem-vindos.
