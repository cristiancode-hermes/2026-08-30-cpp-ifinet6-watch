# ifinet6-watch — Architecture

## Flujo

```
/proc/net/if_inet6  ──► parse_ifinet6_file()  ──► std::vector<Addr>
                                  │
                                  ▼
                     parse_addr32() + compress_ipv6() (RFC 5952)
                                  │
                                  ▼
                     well_known() + scope_name() + flag_names()
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             render_snapshot()            render_json()
                    │
     filtros (iface/scope/flag/global/link/host/ula/perm/top)
                    → watch delta
```

## Decisiones técnicas

- **Monolítico stdlib-only**: un solo TU, `g++ -std=c++23` directo, zero
  dependencias (`<charconv>` no hace falta — los campos hex se parsean
  con `parse_hex()` manual y `%02x`).
- **Formato kernel 6.8**: `%pi6 ifindex plen scope flags ifname`. El
  parser exige ≥6 tokens; los 4 campos numéricos son hex de 2 dígitos.
  Verificado contra el fuente real v6.8 (el campo 1 es el **ifindex**,
  no el scope — pitfall clásico de documentación antigua).
- **Compresión RFC 5952**: run más larga de words cero (≥2), tie -> la
  primera. Caso sin run: forma completa. `parse_addr32` exige 32 chars
  hex exactos.
- **Well-known vs scope**: la clasificación well-known usa prefijos de
  red (doc-range se comprueba ANTES que `global`), el scope usa el campo
  del kernel. `2001:db8:1234::1` -> well-known `doc-range`, scope
  `global`.
- **Dumps tolerantes**: `--file` salta comentarios `#`, líneas vacías y
  filas malformadas (<5 tokens o hex inválido).
- **Paleta ANSI mutable**: `--no-color` vacía las strings de color en
  runtime — afecta por igual a selftest, watch y snapshot.
- **Watch flush**: `render_delta()` y `render_snapshot()` terminan con
  `std::cout << std::flush` para que un `timeout` externo nunca pierda
  frames.
- **JSON a mano**: claves siempre entre comillas; `json_escape` para
  nombres de interfaz.