# Wiring Notes

## Entrance Arduino

| Component | Pin | Notes |
|---|---|---|
| RFID MFRC522 SS | 10 | SPI chip select |
| RFID MFRC522 RST | 9 | Reset |
| RFID MFRC522 MOSI | 11 | SPI (hardware) |
| RFID MFRC522 MISO | 12 | SPI (hardware) |
| RFID MFRC522 SCK | 13 | SPI (hardware) |
| RFID MFRC522 VCC | 3.3V | Do NOT use 5V |
| RFID MFRC522 GND | GND | |
| Servo Motor signal | 6 | PWM |
| Servo Motor VCC | 5V | Add 100uF decoupling cap between 5V and GND near servo to prevent brownout |
| Servo Motor GND | GND | |

> **LCD not currently wired on entrance Arduino.** If added later: SDA -> A4, SCL -> A5.

---

## Cart Arduino

| Component | Pin | Notes |
|---|---|---|
| Keypad Row 1 | 2 | |
| Keypad Row 2 | 3 | |
| Keypad Row 3 | 4 | |
| Keypad Row 4 | 5 | |
| Keypad Col 1 | 6 | |
| Keypad Col 2 | 7 | |
| Keypad Col 3 | 8 | |
| Grove LCD RGB SDA | A4 | I2C (hardware) |
| Grove LCD RGB SCL | A5 | I2C (hardware) |
| Grove LCD RGB VCC | 5V | |
| Grove LCD RGB GND | GND | |
| Fingerprint sensor RX | A0 | SoftwareSerial TX from Arduino |
| Fingerprint sensor TX | A1 | SoftwareSerial RX to Arduino |
| Fingerprint sensor VCC | 3.3V or 5V | Check your specific module; Adafruit sensor is 3.3V logic but tolerates 5V power |
| Fingerprint sensor GND | GND | |

> **Library notes:**
> - LCD uses `rgb_lcd.h` (Seeed Studio Grove RGB LCD Backlight library), not `LiquidCrystal_I2C`.
> - Fingerprint uses `Adafruit_Fingerprint.h` over SoftwareSerial at 57600 baud.
> - Keypad uses the standard `Keypad` library (Mark Stanley / Alexander Brevig).

---

## Fingerprint Enrollment Arduino

A separate third Arduino is used only for enrolling fingerprints onto the sensor's onboard flash.
Wire the fingerprint sensor identically to the cart Arduino (A0/A1 SoftwareSerial), upload the
Adafruit fingerprint enrollment sketch, and note the slot IDs assigned to each finger.
Those slot IDs must then be added to `adminTable[]` in `cart_arduino.ino` before deploying.

---

## General Notes

- All Arduinos share a common GND if powered from the same supply.
- SPI pins 11/12/13 on the entrance Arduino are hardware-fixed; do not reassign them.
- I2C pins A4/A5 on the cart Arduino are hardware-fixed for the Grove LCD.
- SoftwareSerial on A0/A1 for the fingerprint sensor leaves hardware Serial (0/1) free for USB debugging.
