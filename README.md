# Chromebook Cart Security System

> Arduino-based Chromebook sign-out/sign-in tracking system for schools.  
> **Team:** Julian D., Ethan A., Lennon F. — TEJ4M

---

## Problem Statement

Schools that rely on shared Chromebook carts often struggle with tracking which students have borrowed which devices, leading to lost, stolen, or unaccounted-for Chromebooks. This project addresses that gap by developing an Arduino-based sign-in/sign-out system that allows students to log Chromebook loans using a 12-digit keypad and student number, giving administrators a clear, reliable record of device usage and accountability.

---

## Features by Scope

### Primary Scope
- RFID card scan to unlock the Chromebook cart room (servo motor)
- 12-digit keypad on each cart for student number + Chromebook number entry
- Sign-out: links student number to Chromebook number
- Sign-in: detaches Chromebook number from student number
- LCD display on each cart showing instructions and input feedback

### Secondary Scope
- Barcode scanner confirms Chromebook after checkout; alarm triggers if not scanned within a set time
- Fingerprint sensor for admin access (sign out an entire cart at once)

### Tertiary Scope
- Distance sensor monitors if cart is opened without authorization
- AI camera inside cart counts Chromebooks removed; suspicion meter triggers alarm if exceeded
- Room security camera; alarm sounds if data stream is lost

---

## Hardware Components

| Component | Purpose |
|---|---|
| Arduino (x2) | Entrance unit + Cart unit |
| RFID Reader | Room entry authentication |
| 12-digit Keypad | Student/Chromebook number input |
| LCD Display (I2C) | User instructions and feedback |
| Servo Motor | Door lock mechanism |
| Barcode Scanner | Chromebook verification on checkout |
| Fingerprint Sensor | Admin access |
| Distance Sensor (HC-SR04) | Cart open detection |
| Buzzer | Alarm output |

---

## Project Structure

```
chromebook-cart-security/
├── src/
│   ├── entrance_arduino/     # RFID scan + door unlock logic
│   │   └── entrance_arduino.ino
│   └── cart_arduino/         # Keypad, LCD, sign-in/out logic
│       └── cart_arduino.ino
├── docs/
│   ├── design_brief.pdf
│   ├── scope_notes.pdf
│   └── uml_diagrams.md
├── hardware/
│   └── wiring_notes.md
└── README.md
```

---

## UML Diagrams

State machine diagrams for each scope, created with Mermaid:

- [Primary Scope UML](https://mermaid.ai/d/06c06904-7adf-4590-b95f-602c0413bfc8)
- [Secondary Scope UML](https://mermaid.ai/d/2d24661e-4f2a-4950-9454-f2c0c0dd80dd)
- [Tertiary Scope UML](https://mermaid.ai/d/7c4aa2ee-2a1c-42bc-b805-3cc3a1620824)

---

## Getting Started

1. Install the [Arduino IDE](https://www.arduino.cc/en/software)
2. Install required libraries:
   - `MFRC522` (RFID)
   - `LiquidCrystal_I2C` (LCD)
   - `Keypad`
   - `Servo`
   - `Adafruit Fingerprint Sensor Library`
3. Upload `entrance_arduino.ino` to the entrance Arduino
4. Upload `cart_arduino.ino` to each cart Arduino
5. See `hardware/wiring_notes.md` for pin connections

---

## Contributors

- **Julian D.**
- **Ethan A.**
- **Lennon F.**
