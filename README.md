# ifinet6-watch

Monitor de direcciones IPv6 asignadas a interfaces del kernel Linux
(C++23, zero deps).

Lee `/proc/net/if_inet6` (exportado por `if6_seq_show` en
`net/ipv6/addrconf.c`) y muestra cada dirección: forma comprimida
RFC 5952 (`::1`, `fe80::`, `2001:db8::1`), ifindex de la interfaz,
prefijo, scope (`global` / `host` / `link` / `site` / `org`) y flags
`IFA_F_*` (`PERMANENT`, `TENTATIVE`, `DEPRECATED`, `SECONDARY`,
`DADFAILED`, `OPTIMISTIC`, `NODAD`, `HOME`).

## Features

- **Fuente única**: `/proc/net/if_inet6` — todas las `inet6_ifaddr`
- **Compresión RFC 5952**: run más larga de words cero, tie -> primera
  (`2001:db8:0:0:1:0:0:1` -> `2001:db8::1:0:0:1`)
- **Clasificación well-known**: loopback, link-local, ULA (`fc00::/7`),
  doc-range (`2001:db8::/32`), NAT64 (`64:ff9b::/96`), Teredo, 6to4
- **Scope decodificado**: `0x10` host, `0x20` link, `0x40` site, `0x80` org, `0x00` global
- **Flags IFA_F_***: PERMANENT, TENTATIVE, DEPRECATED, SECONDARY,
  DADFAILED, OPTIMISTIC, NODAD, HOME (rojo si dadfailed/deprecated)
- **Modo watch (`--watch N`)**: refresh periódico con deltas
  (nuevas/eliminadas, cambios de flags/scope) y flush por frame
- **Salida JSON (`--json`)**: `summary` + array `addresses` validable
  con `python -m json.tool`
- **Demo mode (`--demo`)**: host sintético con 5 interfaces y 10
  direcciones (permanent, secondary, tentative, deprecated)
- **Filtros**: `--iface`, `--scope`, `--flag`, `--global`, `--link`,
  `--host`, `--ula`, `--permanent`, `--top N`
- **`--file`**: parsea un dump (tolera comentarios `#`)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 75 checks (compresión IPv6, clasificación, scope/flags,
  parser, filtros, demo, JSON, watch, `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o ifinet6-watch
```

## Usage

```bash
# Snapshot único (host real)
./ifinet6-watch

# Solo link-local
./ifinet6-watch --link

# Solo direcciones de una interfaz
./ifinet6-watch --iface eth0

# Solo ULA (fc00::/7)
./ifinet6-watch --ula

# Solo temporales/privacy (IFA_F_SECONDARY)
./ifinet6-watch --flag secondary

# Direcciones en deprecación o con DAD fallido
./ifinet6-watch --flag deprecated

# Modo watch (cada 2s) con deltas
./ifinet6-watch --watch 2

# JSON
./ifinet6-watch --json

# Demo (host sintético)
./ifinet6-watch --demo

# Parsear un dump con comentarios
./ifinet6-watch --file sample-ifinet6.table --no-color

# Sin colores
./ifinet6-watch --no-color

# Auto-tests
./ifinet6-watch --selftest
```

## Data Source

`/proc/net/if_inet6` — formato exacto del kernel 6.8
(`if6_seq_show`, `net/ipv6/addrconf.c`):

```c
seq_printf(seq, "%pi6 %02x %02x %02x %02x %8s\n",
           &ifp->addr,
           ifp->idev->dev->ifindex,   // ifindex (hex)
           ifp->prefix_len,           // 0x80 = /128
           ifp->scope,                // 0x10 host, 0x20 link, ...
           (u8) ifp->flags,           // IFA_F_* (byte bajo)
           ifp->idev->dev->name);
```

Ejemplo real:

```
00000000000000000000000000000001 01 80 10 80       lo
```

→ `::1/128` scope host, PERMANENT, ifindex 1, interfaz `lo`.

### Valores de scope

El campo `scope` es `__ipv6_addr_type(addr) & IPV6_ADDR_SCOPE_MASK`
(`0x00f0`): `0x01` (host) << 4 = `0x10`, `0x02` (link) << 4 = `0x20`,
`0x05` (site) << 4 = `0x50`, `0x08` (org) << 4 = `0x80`, global = `0x00`.

### Flags IFA_F_* (uapi/linux/if_addr.h)

`0x01` SECONDARY, `0x02` NODAD, `0x04` OPTIMISTIC, `0x08` DADFAILED,
`0x10` HOMEADDRESS, `0x20` DEPRECATED, `0x40` TENTATIVE, `0x80`
PERMANENT (los flags > 0xFF no aparecen: el kernel imprime `(u8)`).

## License

MIT