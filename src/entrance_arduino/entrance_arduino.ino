/*
 * Chromebook Cart Security System
 * Entrance Arduino
 *
 * Responsibilities:
 *   - Read RFID card
 *   - Validate against authorized UIDs
 *   - Unlock door via servo on success
 *   - Show feedback on LCD
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

#include <SPI.h>
#include <MFRC522.h>
#include <Servo.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

// --- Pin Definitions ---
#define RST_PIN   9
#define SS_PIN    10
#define SERVO_PIN 6

// --- Objects ---
MFRC522 rfid(SS_PIN, RST_PIN);
Servo doorServo;
LiquidCrystal_I2C lcd(0x27, 16, 2);

// --- Authorized RFID UIDs ---
// Add authorized card UIDs here (4 bytes each)
const byte AUTHORIZED_UIDS[][4] = {
  {0xAA, 0xBB, 0xCC, 0xDD},  // Example card 1
  {0x11, 0x22, 0x33, 0x44},  // Example card 2
};
const int NUM_AUTHORIZED = sizeof(AUTHORIZED_UIDS) / sizeof(AUTHORIZED_UIDS[0]);

// --- Constants ---
const int LOCKED_ANGLE   = 0;
const int UNLOCKED_ANGLE = 90;
const unsigned long UNLOCK_DURATION_MS = 5000;  // Door stays unlocked for 5 seconds
const unsigned long DENY_DURATION_MS   = 3000;  // Deny message duration

// --- State Machine ---
enum EntranceState {
  WAITING_FOR_RFID,
  DOOR_UNLOCKED,
  ACCESS_DENIED_DISPLAY
};

EntranceState currentState = WAITING_FOR_RFID;
unsigned long stateEnteredAt = 0;

void setup() {
  Serial.begin(9600);
  SPI.begin();
  rfid.PCD_Init();

  doorServo.attach(SERVO_PIN);
  doorServo.write(LOCKED_ANGLE);

  lcd.init();
  lcd.backlight();
  lcd.setCursor(0, 0);
  lcd.print("Scan RFID card");

  Serial.println("Entrance system ready.");
}

void loop() {
  unsigned long now = millis();

  // Handle timed state exits (non-blocking)
  if (currentState == DOOR_UNLOCKED && now - stateEnteredAt >= UNLOCK_DURATION_MS) {
    doorServo.write(LOCKED_ANGLE);
    enterState(WAITING_FOR_RFID);
    return;
  }

  if (currentState == ACCESS_DENIED_DISPLAY && now - stateEnteredAt >= DENY_DURATION_MS) {
    enterState(WAITING_FOR_RFID);
    return;
  }

  // Only read RFID when idle
  if (currentState != WAITING_FOR_RFID) return;

  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) {
    return;
  }

  if (isAuthorized(rfid.uid.uidByte)) {
    grantAccess();
  } else {
    denyAccess();
  }

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
}

void enterState(EntranceState newState) {
  currentState = newState;
  stateEnteredAt = millis();

  lcd.clear();
  switch (newState) {
    case WAITING_FOR_RFID:
      lcd.setCursor(0, 0);
      lcd.print("Scan RFID card");
      break;
    case DOOR_UNLOCKED:
      lcd.setCursor(0, 0);
      lcd.print("Access Granted");
      lcd.setCursor(0, 1);
      lcd.print("Door unlocked");
      break;
    case ACCESS_DENIED_DISPLAY:
      lcd.setCursor(0, 0);
      lcd.print("Access Denied");
      break;
  }
}

bool isAuthorized(byte *uid) {
  for (int i = 0; i < NUM_AUTHORIZED; i++) {
    bool match = true;
    for (int j = 0; j < 4; j++) {
      if (uid[j] != AUTHORIZED_UIDS[i][j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

void grantAccess() {
  Serial.println("Access granted.");
  doorServo.write(UNLOCKED_ANGLE);
  enterState(DOOR_UNLOCKED);
}

void denyAccess() {
  Serial.println("Access denied.");
  enterState(ACCESS_DENIED_DISPLAY);
}
