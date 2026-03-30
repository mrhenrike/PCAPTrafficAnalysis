# PCAPTrafficAnalysis

[![Author](https://img.shields.io/badge/author-mrhenrike-black?logo=github)](https://github.com/mrhenrike)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/mrhenrike/PCAPTrafficAnalysis/blob/main/LICENSE)
[![Purpose](https://img.shields.io/badge/purpose-OT%20%2F%20ICS%20%2F%20Lab-red)](https://github.com/mrhenrike/PCAPTrafficAnalysis)

Network packet captures collected in **laboratory and controlled environments** for educational use in OT/ICS security research, training, and tool development.

> **Author:** Andre Henrique ([@mrhenrike](https://github.com/mrhenrike)) — LinkedIn/X: @mrhenrike

**Version 2.0.0** — Histórico Git foi reescrito para um único commit: o clone contém apenas os ficheiros listados abaixo (~2 MiB de dados + metadados), sem blobs legacy no histórico.

---

## Contents (current tree)

| Category | Files | Description |
|----------|-------|-------------|
| **Modbus TCP** | `ICS-Modbus-001.pcap`, `ICS-Modbus-002.pcap`, `ICS-Modbus-003.pcap` | Modbus function codes, read/write coils and registers |
| **Lab field tests** | `ColetaTF01.pcap`, `ColetaTF02.pcapng`, `ColetaTF03.pcap`, `ColetaTF04.pcap`, `ColetaTF05.pcapng` | Sequential captures from controlled ICS lab sessions |

Coleções antigas (4SICS, S4x15, outros protocolos, malware zips) **não estão** neste repositório; commits anteriores a v2.0.0 deixaram de existir em `main`. Para ampliar a coleção, use cópias locais, releases arquivadas ou Git LFS noutro ramo conforme necessidade.

---

## Usage

Open `.pcap` / `.pcapng` files with [Wireshark](https://www.wireshark.org/) or process with `tshark`:

```bash
# Modbus TCP — overview
tshark -r ICS-Modbus-001.pcap -Y "modbus" -T fields -e frame.number -e ip.src -e modbus.func_code

# Modbus — all three files
for f in ICS-Modbus-00*.pcap; do echo "=== $f ==="; tshark -r "$f" -q -z io,stat,0; done

# Lab captures — protocol summary (adjust display filter per capture)
tshark -r ColetaTF01.pcap -q -z io,phs
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
