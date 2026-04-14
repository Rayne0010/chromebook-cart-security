/*
 * Chromebook Cart Security System
 * Cart Arduino
 *
 * Responsibilities:
 *   - 12-digit keypad input for student number
 *   - Barcode scanner (USB HID) identifies which Chromebook to sign out/in
 *   - Sign-out: associate student number with Chromebook number
 *   - Sign-in: clear association for returned Chromebook
 *   - LCD display for user prompts and feedback
 *   - Fingerprint sensor for admin access and bulk cart sign-out/sign-in
 *
 * Sign-out / sign-in flow (Flow B):
 *   Student enters 9-digit student number on keypad, then scans the
 *   Chromebook barcode. The barcode is looked up in cbTable[] to resolve
 *   the CB slot number automatically -- no manual CB number entry required.
 *
 * States (Primary Scope):
 *   S_IDLE -> S_ENTERING_STUDENT_NUMBER
 *   -> S_WAITING_FOR_BARCODE_OUT or S_WAITING_FOR_BARCODE_IN
 *   -> S_SIGN_OUT_SUCCESS / S_SIGN_IN_SUCCESS / S_ERROR_DISPLAY -> S_IDLE
 *
 * States (Secondary Scope - Admin):
 *   S_IDLE --(*)--> S_WAITING_FOR_FINGERPRINT
 *   -> S_ADMIN_MENU
 *   -> S_BULK_CONFIRM -> S_BULK_COMPLETE -> S_IDLE
 *   -> S_BULK_IN_CONFIRM -> S_BULK_IN_COMPLETE -> S_IDLE
 *
 * Fix / change notes:
 *   - Removed recursive enterState() calls from inside updateLCD().
 *   - First keypress in S_IDLE captured after enterState() to avoid wipe.
 *   - checkoutRecords[] changed from int to long; strtol() for parsing.
 *   - Fingerprint confidence threshold lowered to 30.
 *   - checkoutRecords[] persisted to EEPROM; magic number detects first boot.
 *   - SoftwareSerial buffer flushed on entering S_WAITING_FOR_FINGERPRINT.
 *   - Bulk sign-in added; errors if 0 CBs matched.
 *   - String objects replaced with fixed char[] arrays and F() macros.
 *   - 15s input timeout on all input states.
 *   - Bulk op count displayed on completion screen.
 *   - Cart mode (INDIVIDUAL / BULK) persisted in EEPROM, toggled from admin menu.
 *   - Admin number entry removed; fingerID looked up in adminTable[].
 *   - currentAdminNumber char[] replaced with long currentAdminNum.
 *   - Barcode scanner integrated (Flow B): students scan instead of typing a
 *     CB number. cbTable[] maps barcode strings to slot numbers 1-30.
 *   - BarcodeParser uses OnKeyDown() (USB Host Shield Library 2.0 API).
 *   - State enum renamed CartState; enterState() takes int to avoid Arduino
 *     IDE prototype-generator conflict with CartState.
 *   - cbTable[] and adminTable[] moved to PROGMEM; lookup functions updated
 *     to use pgm_read_ptr / pgm_read_word / pgm_read_byte / pgm_read_dword.
 *     Saves ~355 bytes of SRAM (was at 85% usage, now ~67%).
 *   - BarcodeParser.buf reduced from 32 to 16 bytes; barcodes are at most
 *     10 chars in this deployment.
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

#include <avr/pgmspace.h>
#include <SPI.h>
#include <usbhub.h>
#include <hidboot.h>
#include <Keypad.h>
#include <Wire.h>
#include <rgb_lcd.h>
#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>
#include <EEPROM.h>

// =============================================================================
// Hardware Setup
// =============================================================================

// --- Keypad ---
const byte ROWS = 4;
const byte COLS = 3;
char keys[ROWS][COLS] = {
  {'1','2','3'},
  {'4','5','6'},
  {'7','8','9'},
  {'*','0','#'}
};
byte rowPins[ROWS] = {2, 3, 4, 5};
byte colPins[COLS] = {6, 7, 8};
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

// --- LCD ---
rgb_lcd lcd;

// --- Fingerprint Sensor ---
// SoftwareSerial: RX = A0, TX = A1.
SoftwareSerial fingerprintSerial(A0, A1);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&fingerprintSerial);

// --- USB Host Shield + Barcode Scanner ---
// ARCELI USB Host Shield (MAX3421E). Hardwires pin 9 (INT) and pin 10 (SS).
USB Usb;
USBHub Hub(&Usb);
HIDBoot<USB_HID_PROTOCOL_KEYBOARD> HidKeyboard(&Usb);

class BarcodeParser : public KeyboardReportParser {
public:
  char    buf[16];   // 15 chars + null; barcodes in this deployment are <= 10 chars
  bool    ready;
  uint8_t len;

  BarcodeParser() : ready(false), len(0) { buf[0] = '\0'; }

  void reset() {
    len    = 0;
    buf[0] = '\0';
    ready  = false;
  }

protected:
  void OnKeyDown(uint8_t mod, uint8_t key) {
    if (key == 0x28) {  // Enter: barcode complete
      buf[len] = '\0';
      ready    = true;
      return;
    }
    uint8_t c = OemToAscii(mod, key);
    if (c == 0) return;
    if (len < 15) {
      buf[len++] = (char)c;
    }
  }
};

BarcodeParser barcodeParser;

// =============================================================================
// Barcode -> Chromebook Lookup Table (PROGMEM)
// =============================================================================

// String literals in PROGMEM. Slots 1 and 7 have real barcodes; others are
// placeholders that will never match a real scan.
// HOW TO UPDATE: replace the matching placeholder string below with the real
// barcode string read from Serial Monitor, then re-upload.
const char PROGMEM cb_s01[] = "5CG0316P3P";  // real
const char PROGMEM cb_s02[] = "CB_02";
const char PROGMEM cb_s03[] = "CB_03";
const char PROGMEM cb_s04[] = "CB_04";
const char PROGMEM cb_s05[] = "CB_05";
const char PROGMEM cb_s06[] = "CB_06";
const char PROGMEM cb_s07[] = "1H85392GMX";  // real
const char PROGMEM cb_s08[] = "CB_08";
const char PROGMEM cb_s09[] = "CB_09";
const char PROGMEM cb_s10[] = "CB_10";
const char PROGMEM cb_s11[] = "CB_11";
const char PROGMEM cb_s12[] = "CB_12";
const char PROGMEM cb_s13[] = "CB_13";
const char PROGMEM cb_s14[] = "CB_14";
const char PROGMEM cb_s15[] = "CB_15";
const char PROGMEM cb_s16[] = "CB_16";
const char PROGMEM cb_s17[] = "CB_17";
const char PROGMEM cb_s18[] = "CB_18";
const char PROGMEM cb_s19[] = "CB_19";
const char PROGMEM cb_s20[] = "CB_20";
const char PROGMEM cb_s21[] = "CB_21";
const char PROGMEM cb_s22[] = "CB_22";
const char PROGMEM cb_s23[] = "CB_23";
const char PROGMEM cb_s24[] = "CB_24";
const char PROGMEM cb_s25[] = "CB_25";
const char PROGMEM cb_s26[] = "CB_26";
const char PROGMEM cb_s27[] = "CB_27";
const char PROGMEM cb_s28[] = "CB_28";
const char PROGMEM cb_s29[] = "CB_29";
const char PROGMEM cb_s30[] = "CB_30";

struct CBEntry {
  const char* barcode;  // pointer to PROGMEM string
  int         cbNumber;
};

// The struct array itself is also in PROGMEM.
const CBEntry PROGMEM cbTable[] = {
  { cb_s01, 1  }, { cb_s02, 2  }, { cb_s03, 3  }, { cb_s04, 4  },
  { cb_s05, 5  }, { cb_s06, 6  }, { cb_s07, 7  }, { cb_s08, 8  },
  { cb_s09, 9  }, { cb_s10, 10 }, { cb_s11, 11 }, { cb_s12, 12 },
  { cb_s13, 13 }, { cb_s14, 14 }, { cb_s15, 15 }, { cb_s16, 16 },
  { cb_s17, 17 }, { cb_s18, 18 }, { cb_s19, 19 }, { cb_s20, 20 },
  { cb_s21, 21 }, { cb_s22, 22 }, { cb_s23, 23 }, { cb_s24, 24 },
  { cb_s25, 25 }, { cb_s26, 26 }, { cb_s27, 27 }, { cb_s28, 28 },
  { cb_s29, 29 }, { cb_s30, 30 },
};
const int CB_TABLE_SIZE = sizeof(cbTable) / sizeof(cbTable[0]);

// Reads each entry from PROGMEM and compares with strcmp_P.
// Returns the cart slot number, or -1 if not found.
int lookupCBNumber(const char* barcode) {
  for (int i = 0; i < CB_TABLE_SIZE; i++) {
    const char* stored = (const char*)pgm_read_ptr(&cbTable[i].barcode);
    if (strcmp_P(barcode, stored) == 0) {
      return pgm_read_word(&cbTable[i].cbNumber);
    }
  }
  return -1;
}

// =============================================================================
// State Machine
// =============================================================================

// Prefixed S_ to avoid collision with Keypad library's KeyState enum.
enum CartState {
  S_IDLE,
  S_ENTERING_STUDENT_NUMBER,
  S_WAITING_FOR_BARCODE_OUT,
  S_WAITING_FOR_BARCODE_IN,
  S_SIGN_OUT_SUCCESS,
  S_SIGN_IN_SUCCESS,
  S_ERROR_DISPLAY,
  S_WAITING_FOR_FINGERPRINT,
  S_ADMIN_MENU,
  S_BULK_CONFIRM,
  S_BULK_COMPLETE,
  S_BULK_IN_CONFIRM,
  S_BULK_IN_COMPLETE
};

CartState currentState = S_IDLE;

// =============================================================================
// Data
// =============================================================================

const int MAX_CHROMEBOOKS = 30;
long checkoutRecords[MAX_CHROMEBOOKS];  // must stay in SRAM for fast access

// EEPROM layout:
//   Bytes   0-119: checkoutRecords (30 longs x 4 bytes)
//   Bytes 120-123: magic number
//   Byte    124:   cartMode
const int  EEPROM_BASE_ADDR      = 0;
const int  EEPROM_MAGIC_ADDR     = MAX_CHROMEBOOKS * sizeof(long);
const long EEPROM_MAGIC          = 12345678L;
const int  EEPROM_CART_MODE_ADDR = EEPROM_MAGIC_ADDR + sizeof(long);

byte cartMode = 0;  // 0 = INDIVIDUAL, 1 = BULK

const int STUDENT_NUMBER_LENGTH = 9;

const unsigned long FINGERPRINT_TIMEOUT_MS      = 10000;
const unsigned long INPUT_TIMEOUT_MS            = 15000;
const unsigned long MESSAGE_DISPLAY_DURATION_MS = 3000;

char inputBuffer[10]          = "";
char currentStudentNumber[10] = "";
long currentAdminNum          = 0;
char currentCN[3]             = "";
char errorMessage[17]         = "";

unsigned long stateEnteredAt = 0;
int lastBulkCount = 0;

// =============================================================================
// EEPROM Helpers
// =============================================================================

void saveRecord(int index) {
  EEPROM.put(EEPROM_BASE_ADDR + index * sizeof(long), checkoutRecords[index]);
}

void saveCartMode() {
  EEPROM.put(EEPROM_CART_MODE_ADDR, cartMode);
}

void loadRecords() {
  long magic;
  EEPROM.get(EEPROM_MAGIC_ADDR, magic);
  if (magic != EEPROM_MAGIC) {
    for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
      checkoutRecords[i] = 0;
      EEPROM.put(EEPROM_BASE_ADDR + i * sizeof(long), checkoutRecords[i]);
    }
    cartMode = 0;
    EEPROM.put(EEPROM_CART_MODE_ADDR, cartMode);
    EEPROM.put(EEPROM_MAGIC_ADDR, EEPROM_MAGIC);
    Serial.println(F("EEPROM initialized."));
  } else {
    for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
      EEPROM.get(EEPROM_BASE_ADDR + i * sizeof(long), checkoutRecords[i]);
    }
    EEPROM.get(EEPROM_CART_MODE_ADDR, cartMode);
    if (cartMode != 0 && cartMode != 1) cartMode = 0;
    Serial.println(F("Records loaded from EEPROM."));
  }
}

// =============================================================================
// Admin Fingerprint Lookup Table (PROGMEM)
// =============================================================================

struct AdminEntry {
  uint8_t fingerID;
  long    adminNumber;
};

const AdminEntry PROGMEM adminTable[] = {
  { 1, 100000001L }, { 2, 100000001L }, { 3, 100000001L },
  { 4, 100000002L }, { 5, 100000002L }, { 6, 100000002L },
  { 7, 100000003L }, { 8, 100000003L }, { 9, 100000003L },
};
const int ADMIN_TABLE_SIZE = sizeof(adminTable) / sizeof(adminTable[0]);

long lookupAdminNumber(uint8_t fpID) {
  for (int i = 0; i < ADMIN_TABLE_SIZE; i++) {
    if (pgm_read_byte(&adminTable[i].fingerID) == fpID) {
      return pgm_read_dword(&adminTable[i].adminNumber);
    }
  }
  return 0;
}

// =============================================================================
// Setup
// =============================================================================

void setup() {
  Serial.begin(9600);

  lcd.begin(16, 2);
  lcd.setRGB(0, 255, 0);

  loadRecords();

  finger.begin(57600);
  if (finger.verifyPassword()) {
    Serial.println(F("Fingerprint sensor found."));
  } else {
    Serial.println(F("Fingerprint sensor not found."));
  }

  if (Usb.Init() == -1) {
    Serial.println(F("USB shield init failed."));
  } else {
    Serial.println(F("USB Host Shield ready."));
  }
  HidKeyboard.SetReportParser(0, &barcodeParser);

  enterState(S_IDLE);
  Serial.println(F("Cart system ready."));
}

// =============================================================================
// Main Loop
// =============================================================================

void loop() {
  Usb.Task();
  char key = keypad.getKey();

  switch (currentState) {

    case S_IDLE:
      if (key && key != '*' && key != '#') {
        enterState(S_ENTERING_STUDENT_NUMBER);
        inputBuffer[0] = key;
        inputBuffer[1] = '\0';
        updateLCDInput();
      } else if (key == '*') {
        enterState(S_WAITING_FOR_FINGERPRINT);
      }
      break;

    case S_ENTERING_STUDENT_NUMBER:
      if (millis() - stateEnteredAt >= INPUT_TIMEOUT_MS) { enterState(S_IDLE); break; }
      handleStudentNumberInput(key);
      break;

    case S_WAITING_FOR_BARCODE_OUT:
    case S_WAITING_FOR_BARCODE_IN:
      if (millis() - stateEnteredAt >= INPUT_TIMEOUT_MS) { enterState(S_IDLE); break; }
      if (key == '*') { enterState(S_IDLE); break; }
      handleBarcodeInput();
      break;

    case S_ERROR_DISPLAY:
    case S_SIGN_OUT_SUCCESS:
    case S_SIGN_IN_SUCCESS:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) enterState(S_IDLE);
      break;

    case S_WAITING_FOR_FINGERPRINT:
      if (key == '*') { enterState(S_IDLE); break; }
      handleFingerprintInput();
      break;

    case S_ADMIN_MENU:
      if (key == '1') {
        cartMode = 1 - cartMode;
        saveCartMode();
        Serial.print(F("Cart mode: "));
        Serial.println(cartMode == 1 ? F("BULK") : F("INDIVIDUAL"));
        updateLCD();
      } else if (key == '2') {
        enterState(S_BULK_IN_CONFIRM);
      } else if (key == '3') {
        enterState(S_BULK_CONFIRM);
      } else if (key == '*') {
        enterState(S_IDLE);
      }
      break;

    case S_BULK_CONFIRM:
      if (key == '#') processBulkSignOut();
      else if (key == '*') enterState(S_ADMIN_MENU);
      break;

    case S_BULK_COMPLETE:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) enterState(S_IDLE);
      break;

    case S_BULK_IN_CONFIRM:
      if (key == '#') processBulkSignIn();
      else if (key == '*') enterState(S_ADMIN_MENU);
      break;

    case S_BULK_IN_COMPLETE:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) enterState(S_IDLE);
      break;

    default:
      break;
  }
}

// =============================================================================
// Input Handlers
// =============================================================================

void handleStudentNumberInput(char key) {
  if (!key) return;
  if (key == '*') { enterState(S_IDLE); return; }

  if (key != '#') {
    int len = strlen(inputBuffer);
    if (len < STUDENT_NUMBER_LENGTH) {
      inputBuffer[len]     = key;
      inputBuffer[len + 1] = '\0';
      updateLCDInput();
    }
  }

  if (strlen(inputBuffer) == STUDENT_NUMBER_LENGTH) {
    strncpy(currentStudentNumber, inputBuffer, 10);
    inputBuffer[0] = '\0';
    checkOpenRecord();
  }
}

void handleBarcodeInput() {
  if (!barcodeParser.ready) return;

  int cbNum = lookupCBNumber(barcodeParser.buf);
  Serial.print(F("Barcode: "));
  Serial.print(barcodeParser.buf);
  Serial.print(F(" -> CB "));
  Serial.println(cbNum);
  barcodeParser.reset();

  if (cbNum == -1) { showError("Unknown barcode"); return; }

  itoa(cbNum, currentCN, 10);

  if (currentState == S_WAITING_FOR_BARCODE_OUT) confirmSignOut();
  else confirmSignIn();
}

void handleFingerprintInput() {
  if (millis() - stateEnteredAt >= FINGERPRINT_TIMEOUT_MS) { showError("Scan timeout"); return; }

  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) return;
  if (p != FINGERPRINT_OK) { showError("Sensor error"); return; }

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) { showError("Image error"); return; }

  p = finger.fingerSearch();
  if (p == FINGERPRINT_OK && finger.confidence >= 30) {
    long adminNum = lookupAdminNumber(finger.fingerID);
    if (adminNum == 0) { showError("Not registered"); return; }
    currentAdminNum = adminNum;
    Serial.print(F("Admin: ")); Serial.println(currentAdminNum);
    enterState(S_ADMIN_MENU);
  } else {
    showError("Access denied");
  }
}

// =============================================================================
// Business Logic
// =============================================================================

void checkOpenRecord() {
  if (cartMode == 1) { showError("Bulk cart only"); return; }

  long studentNum = strtol(currentStudentNumber, NULL, 10);
  int openCN = -1;
  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == studentNum) { openCN = i + 1; break; }
  }

  if (openCN == -1) enterState(S_WAITING_FOR_BARCODE_OUT);
  else              enterState(S_WAITING_FOR_BARCODE_IN);
}

void confirmSignOut() {
  int cn = atoi(currentCN);
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  if (cn < 1 || cn > MAX_CHROMEBOOKS) { showError("Invalid CB #"); return; }
  if (checkoutRecords[cn - 1] != 0)   { showError("CB unavailable"); return; }

  checkoutRecords[cn - 1] = studentNum;
  saveRecord(cn - 1);
  Serial.print(F("Signed out: ")); Serial.print(studentNum);
  Serial.print(F(" -> CB ")); Serial.println(cn);
  enterState(S_SIGN_OUT_SUCCESS);
}

void confirmSignIn() {
  int cn = atoi(currentCN);
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  if (cn < 1 || cn > MAX_CHROMEBOOKS)        { showError("Invalid CB #"); return; }
  if (checkoutRecords[cn - 1] != studentNum) { showError("No match found"); return; }

  checkoutRecords[cn - 1] = 0;
  saveRecord(cn - 1);
  Serial.print(F("Signed in: CB ")); Serial.print(cn);
  Serial.print(F(" from ")); Serial.println(studentNum);
  enterState(S_SIGN_IN_SUCCESS);
}

void processBulkSignOut() {
  if (cartMode == 0) { showError("Individ. cart"); return; }
  long adminNum = currentAdminNum;
  int count = 0;
  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == 0) { checkoutRecords[i] = adminNum; saveRecord(i); count++; }
  }
  lastBulkCount = count;
  Serial.print(F("Bulk out by ")); Serial.print(adminNum);
  Serial.print(F(": ")); Serial.print(count); Serial.println(F(" CBs."));
  enterState(S_BULK_COMPLETE);
}

void processBulkSignIn() {
  if (cartMode == 0) { showError("Individ. cart"); return; }
  long adminNum = currentAdminNum;
  int count = 0;
  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == adminNum) { checkoutRecords[i] = 0; saveRecord(i); count++; }
  }
  if (count == 0) { showError("No CBs found"); return; }
  lastBulkCount = count;
  Serial.print(F("Bulk in by ")); Serial.print(adminNum);
  Serial.print(F(": ")); Serial.print(count); Serial.println(F(" CBs."));
  enterState(S_BULK_IN_COMPLETE);
}

void showError(const char* msg) {
  strncpy(errorMessage, msg, 16);
  errorMessage[16] = '\0';
  enterState(S_ERROR_DISPLAY);
}

// =============================================================================
// State Transition
// =============================================================================

// Parameter is int (not CartState) to prevent the Arduino IDE prototype
// generator from inserting a prototype before CartState is defined.
void enterState(int newState) {
  currentState   = (CartState)newState;
  stateEnteredAt = millis();
  inputBuffer[0] = '\0';

  if (newState == S_WAITING_FOR_FINGERPRINT) {
    while (fingerprintSerial.available()) fingerprintSerial.read();
  }
  if (newState == S_WAITING_FOR_BARCODE_OUT || newState == S_WAITING_FOR_BARCODE_IN) {
    barcodeParser.reset();
  }

  updateLCD();
}

// =============================================================================
// Display
// =============================================================================

void updateLCD() {
  lcd.clear();
  switch (currentState) {

    case S_IDLE:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      if (cartMode == 1) {
        lcd.print(F("Bulk cart"));
        lcd.setCursor(0, 1); lcd.print(F("Admin accs only"));
      } else {
        lcd.print(F("Enter student #"));
      }
      break;

    case S_ENTERING_STUDENT_NUMBER:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0); lcd.print(F("Student #:"));
      lcd.setCursor(0, 1); lcd.print(inputBuffer);
      break;

    case S_WAITING_FOR_BARCODE_OUT:
      lcd.setRGB(255, 165, 0);
      lcd.setCursor(0, 0); lcd.print(F("Sign OUT"));
      lcd.setCursor(0, 1); lcd.print(F("Scan barcode..."));
      break;

    case S_WAITING_FOR_BARCODE_IN:
      lcd.setRGB(0, 100, 255);
      lcd.setCursor(0, 0); lcd.print(F("Sign IN"));
      lcd.setCursor(0, 1); lcd.print(F("Scan barcode..."));
      break;

    case S_SIGN_OUT_SUCCESS:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0); lcd.print(F("Signed OUT!"));
      lcd.setCursor(0, 1); lcd.print(F("CB #")); lcd.print(currentCN);
      break;

    case S_SIGN_IN_SUCCESS:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0); lcd.print(F("Signed IN!"));
      lcd.setCursor(0, 1); lcd.print(F("CB #")); lcd.print(currentCN);
      break;

    case S_ERROR_DISPLAY:
      lcd.setRGB(255, 0, 0);
      lcd.setCursor(0, 0); lcd.print(F("Error:"));
      lcd.setCursor(0, 1); lcd.print(errorMessage);
      break;

    case S_WAITING_FOR_FINGERPRINT:
      lcd.setRGB(128, 0, 128);
      lcd.setCursor(0, 0); lcd.print(F("Admin: scan"));
      lcd.setCursor(0, 1); lcd.print(F("fingerprint..."));
      break;

    case S_ADMIN_MENU:
      lcd.setRGB(128, 0, 128);
      lcd.setCursor(0, 0);
      lcd.print(cartMode == 1 ? F("ADMIN [BULK]   ") : F("ADMIN [INDIVID]"));
      lcd.setCursor(0, 1); lcd.print(F("1:Md 2:In 3:Out"));
      break;

    case S_BULK_CONFIRM:
      lcd.setRGB(255, 165, 0);
      lcd.setCursor(0, 0); lcd.print(F("Sign out ALL?"));
      lcd.setCursor(0, 1); lcd.print(F("#:Yes    *:No"));
      break;

    case S_BULK_COMPLETE:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0); lcd.print(F("Bulk OUT done!"));
      lcd.setCursor(0, 1); lcd.print(lastBulkCount); lcd.print(F(" CBs signed out"));
      break;

    case S_BULK_IN_CONFIRM:
      lcd.setRGB(255, 165, 0);
      lcd.setCursor(0, 0); lcd.print(F("Sign in ALL?"));
      lcd.setCursor(0, 1); lcd.print(F("#:Yes    *:No"));
      break;

    case S_BULK_IN_COMPLETE:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0); lcd.print(F("Bulk IN done!"));
      lcd.setCursor(0, 1); lcd.print(lastBulkCount); lcd.print(F(" CBs returned"));
      break;

    default: break;
  }
}

void updateLCDInput() {
  lcd.setCursor(0, 1);
  lcd.print(F("                "));
  lcd.setCursor(0, 1);
  lcd.print(inputBuffer);
}
