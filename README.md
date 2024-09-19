
## TX datapath
```
 ┌─────────────────────────────────┐
 │Host                             │
 │                                 │ First packet:
 │   ┌────────┐ tx burst           │ 1. VM0 pings 8.8.8.8
 │   │DOCA app┼─┐  ┌────────────┐  │ 2. packet leaves VM through VF0
 │   └─────▲──┘ │  │VM          │  │ 3. packet arrives in NIC's eswitch FDB
 │         │    │  │     ping   │  │ 4. packet hits tx root pipe, fwd-hit
 │ rx burst│    │  │      │     │  │ 5. packet hits geneve pipe, fwd-miss
 │   ┌─────┼──┐ │  │     ┌▼──┐  │  │ 6. packet hits rss pipe, fwd-rss
 │   │PF Rx Q0│ │  │     │VF0│  │  │ 7. Application PMD rx-bursts packet
 └─────────▲────┼──────────┬───────┘ 8. Business logic to determine
 ┌─────────┼────┼──────────┼───────┐     - geneve header
 │ConnectX7│NIC └───────┐  │       │     - ipsec header
 │ ┌───────┼────────────┼──┼─────┐ │     - vlan header
 │ │       │       ┌────▼──▼───┐ │ │ 9. Offload to geneve/ipsec/vlan pipes
 │ │    all│       │tx root    │ │ │ 10. Application PMD tx-bursts packet
 │ │┌──────┼─┐     └──────────┬┘ │ │ 11. packet hits rx root pipe, fwd-hit
 │ ││rss pipe│            all │  │ │ 12. packet hits geneve pipe, fwd-hit
 │ │└──────▲─┘ miss┌──────────▼┐ │ │ 13. packet hits ipsec pipe, fwd-hit
 │ │       └───────┼geneve pipe│ │ │ 14. packet hits vlan pipe, fwd-hit
 │ │               └──────────┬┘ │ │ 15. packet leaves NIC
 │ │                      hit │  │ │
 │ │          miss ┌──────────▼┐ │ │
 │ │            ┌──┼ipsec pipe │ │ │
 │ │            ▼  └──────────┬┘ │ │
 │ │                      hit │  │ │
 │ │          miss ┌──────────▼┐ │ │
 │ │            ┌──┼vlan pipe  │ │ │
 │ │            ▼  └──────────┬┘ │ │
 │ │ eswitch FDB              │  │ │
 │ └──────────────────────────┼──┘ │
 └────────────────────────────▼────┘
```