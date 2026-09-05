# Fictional plant story: “Clearwater Tank / Valve Yard”

Conpot’s **default** template emulates a Siemens S7-200–style PLC (HTTP “HMI”,
Modbus TCP, SNMP, S7comm, …). For class storytelling we treat that PLC as the
controller for a small **municipal water tank** — not a real plant.

## Narrative

- Site name (story): **Clearwater Tank Station CW-01**
- PLC role: open/close discharge & fill **valves**, read **tank level / pressure**,
  hold **setpoints** for pump speed
- Attackers who speak Modbus will look like they are probing ICS assets even
  though every response is honeypot fiction

## Modbus map (default template → story labels)

| Modbus area | Addresses (default) | Story meaning |
| --- | --- | --- |
| **Coils** (binary outputs) | 1–128 | Valves / actuators — e.g. coil 1 = fill valve open/close, coil 2 = discharge valve, coil 3 = pump enable |
| **Discrete inputs** | 10001–10032 | Sensors — float switch high/low, hatch open, power OK |
| **Analog inputs** | 30001–30008 | Tank level (%), discharge pressure (PSI×10), inflow rate |
| **Holding registers** | 40001–40008 | Operator setpoints — level target, pump speed %, alarm thresholds |

Slave IDs in the default template include `0`, `1`, `2`, and `255`. Slave **2**
is the one with analog + holding blocks (the “instrumentation” unit in our story).

## Why this matters for reports

When `scripts/analyze_all.py` shows Modbus **function codes**, map them like this:

| FC | Name | Class interpretation |
| ---: | --- | --- |
| 1 | Read Coils | Recon of valve states |
| 2 | Read Discrete Inputs | Sensor sweep |
| 3 | Read Holding Registers | Setpoint / config read |
| 4 | Read Input Registers | Level / pressure read |
| 5 / 15 | Write Single / Multiple Coils | Attempt to open/close valves |
| 6 / 16 | Write Holding Registers | Attempt to change setpoints |

No real process is controlled. Captured traffic is **telemetry only**.
