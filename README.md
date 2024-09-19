
## TX datapath
```
 ┌─────────────────────────────────┐
 │Host                             │ First packet:
 │                                 │ 1. VM0 pings 8.8.8.8
 │                                 │ 2. packet leaves VM through VF0
 │   ┌────────┐ tx burst           │ 3. packet arrives in NIC's eswitch FDB
 │   │DOCA app┼─┐  ┌────────────┐  │ 4. packet hits tx root pipe, fwd-hit
 │   └─────▲──┘ │  │VM          │  │ 5. packet hits geneve pipe, fwd-miss
 │         │    │  │     ping   │  │ 6. packet hits rss pipe, fwd-rss
 │ rx burst│    │  │      │     │  │ 7. Application PMD rx-bursts packet
 │   ┌─────┼──┐ │  │     ┌▼──┐  │  │ 8. Business logic to determine
 │   │PF Rx Q0│ │  │     │VF0│  │  │     - geneve header
 └─────────▲────┼──────────┬───────┘     - ipsec header
 ┌─────────┼────┼──────────┼───────┐     - vlan header
 │ConnectX7│NIC └───────┐  │       │ 9. Offload to geneve/ipsec/vlan pipes
 │ ┌───────┼────────────┼──┼─────┐ │ 10. Application PMD tx-bursts packet
 │ │       │       ┌────▼──▼───┐ │ │ 11. packet hits rx root pipe, fwd-hit
 │ │    all│       │tx root    │ │ │ 12. packet hits geneve pipe, fwd-hit
 │ │┌──────┼─┐     └──────────┬┘ │ │ 13. packet hits ipsec pipe, fwd-hit
 │ ││rss pipe│            all │  │ │ 14. packet hits vlan pipe, fwd-hit
 │ │└──────▲─┘ miss┌──────────▼┐ │ │ 15. packet leaves NIC
 │ │       └───────┼geneve pipe│ │ │
 │ │               └──────────┬┘ │ │
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