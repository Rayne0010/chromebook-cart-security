/*
 * ChromeLock -- Barcode Scanner Test
 *
 * Standalone test sketch for the WAVE-14810 barcode scanner.
 * Uses the same SoftwareSerial pins and baud rate as cart_arduino.ino.
 * Does NOT require the keypad, LCD, fingerprint sensor, or servo.
 *
 * Wiring (same as production):
 *   Scanner TX  -> Arduino pin 9  (SoftwareSerial RX)
 *   Scanner RX  -> Arduino pin 10 (SoftwareSerial TX)
 *   Scanner VCC -> 5V
 *   Scanner GND -> GND
 *
 * IMPORTANT -- one-time scanner setup (if not already done):
 *   The scanner must be in Sensing Mode and UART output mode before this
 *   sketch will receive anything. Scan the config barcodes from the
 *   WAVE-14810 V2.1 manual once using a computer to configure the scanner,
 *   then switch to this Arduino sketch. Settings persist in the scanner's
 *   own EEPROM across power cycles.
 *
 * Usage:
 *   1. Upload to the cart Arduino.
 *   2. Open Serial Monitor at 9600 baud.
 *   3. Wave a Chromebook barcode in front of the scanner lens.
 *   4. The raw barcode string and a lookup result are printed.
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

#include <SoftwareSerial.h>

// Same pins as cart_arduino.ino
SoftwareSerial barcodeSerial(9, 10);  // RX = pin 9, TX = pin 10

// Same buffer size as cart_arduino.ino
const byte BARCODE_BUFFER_SIZE = 24;
char barcodeBuffer[BARCODE_BUFFER_SIZE] = "";
byte barcodePos = 0;

// ----------------------------------------------------------------------------
// Lookup table -- only real confirmed entries + placeholders for the rest.
// Replace placeholders with actual asset-tag barcodes as you capture them.
// The two confirmed entries are tested directly; placeholders will return
// "Unknown barcode" which is the expected result until they are populated.
// ----------------------------------------------------------------------------
struct CBEntry {
  const char* barcode;
  uint8_t     cbNumber;
};

const CBEntry cbTable[] = {
  { "5CG0316P3P",    1 },  // confirmed CB #1
  { "1H85392GMX",    7 },  // confirmed CB #7
  // Add real barcodes here as you scan them:
  // { "BARCODE_HERE",  2 },
  // { "BARCODE_HERE",  3 },
  // ... (up to 30 total)
};
const int CB_TABLE_SIZE = sizeof(cbTable) / sizeof(cbTable[0]);

int lookupCBNumber(const char* barcode) {
  for (int i = 0; i < CB_TABLE_SIZE; i++) {
    if (strcmp(barcode, cbTable[i].barcode) == 0) {
      return cbTable[i].cbNumber;
    }
  }
  return 0;
}

// ----------------------------------------------------------------------------

void setup() {
  Serial.begin(9600);
  barcodeSerial.begin(9600);
  barcodeSerial.listen();

  Serial.println(F("=== ChromeLock Barcode Scanner Test ==="));
  Serial.println(F("Wave a Chromebook barcode in front of the scanner."));
  Serial.println(F("Waiting for scan..."));
  Serial.println();
}

void loop() {
  while (barcodeSerial.available()) {
    char c = barcodeSerial.read();

    if (c == '\r' || c == '\n') {
      if (barcodePos > 0) {
        barcodeBuffer[barcodePos] = '\0';
        handleScan(barcodeBuffer);
        barcodePos = 0;
      }
    } else if (c >= ' ' && c <= '~') {
      if (barcodePos < BARCODE_BUFFER_SIZE - 1) {
        barcodeBuffer[barcodePos++] = c;
      } else {
        // Overflow: barcode longer than buffer; discard and reset
        Serial.println(F("[ERROR] Barcode too long for buffer -- increase BARCODE_BUFFER_SIZE"));
        barcodePos = 0;
      }
    }
  }
}

void handleScan(const char* barcode) {
  Serial.print(F("Scanned: \""));
  Serial.print(barcode);
  Serial.print(F("\"  ("));
  Serial.print(strlen(barcode));
  Serial.println(F(" chars)"));

  int cbNum = lookupCBNumber(barcode);
  if (cbNum == 0) {
    Serial.println(F("  Result : Unknown barcode -- not in table"));
    Serial.println(F("           (add it to cbTable[] in both this sketch and cart_arduino.ino)"));
  } else {
    Serial.print(F("  Result : Matched CB #"));
    Serial.println(cbNum);
  }

  Serial.println();
}
