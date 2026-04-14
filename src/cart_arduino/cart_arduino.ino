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
 *   - checkoutRecords[] changed from int to long; student number parsing
 *     changed to strtol() to handle 9-digit numbers on 16-bit Arduino int.
 *   - Fingerprint confidence threshold lowered to 30 for consumer-grade sensors.
 *   - checkoutRecords[] persisted to EEPROM; magic number detects first boot.
 *   - SoftwareSerial buffer flushed on entering S_WAITING_FOR_FINGERPRINT.
 *   - Bulk sign-in added; errors if 0 CBs matched.
 *   - String objects replaced with fixed char[] arrays and F() macros.
 *   - 15s input timeout on all input states.
 *   - Bulk op count displayed on completion screen.
 *   - Cart mode (INDIVIDUAL / BULK) persisted in EEPROM, toggled from admin menu.
 *   - Admin number entry removed; fingerID looked up in compile-time adminTable[].
 *   - currentAdminNumber char[] replaced with long currentAdminNum (removes
 *     redundant ltoa/strtol round-trip).
 *   - Barcode scanner integrated (Flow B): S_ENTERING_CN_OUT, S_ENTERING_CN_IN,
 *     handleCNInput(), and CN_LENGTH removed. Students scan instead of typing
 *     a CB number. cbTable[] maps barcode strings to slot numbers 1-30.
 *     Placeholders ("CB_##") cover slots whose barcodes are not yet known.
 *   - BarcodeParser accumulates HID keyboard characters until Enter (\r),
 *     then sets ready flag. barcodeParser.reset() called on every barcode-wait
 *     state entry. Usb.Task() called every loop iteration unconditionally.
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

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
// 4x3 matrix keypad. Rows on pins 2-5, columns on pins 6-8.
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
// Grove LCD RGB Backlight on I2C (A4/A5). No address needed; handled by library.
rgb_lcd lcd;

// --- Fingerprint Sensor ---
// Adafruit fingerprint sensor on SoftwareSerial: RX = pin A0, TX = pin A1.
SoftwareSerial fingerprintSerial(A0, A1);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&fingerprintSerial);

// --- USB Host Shield + Barcode Scanner ---
// ARCELI USB Host Shield (MAX3421E). Hardwires pin 9 (INT) and pin 10 (SS).
// The barcode scanner enumerates as a USB HID keyboard device.
// BarcodeParser accumulates characters until Enter (\r) signals end of barcode.
USB Usb;
USBHub Hub(&Usb);
HIDBoot<USB_HID_PROTOCOL_KEYBOARD> HidKeyboard(&Usb);

class BarcodeParser : public KeyboardReportParser {
public:
  char    buf[32];
  bool    ready;
  uint8_t len;

  BarcodeParser() : ready(false), len(0) { buf[0] = '\0'; }

  void reset() {
    len    = 0;
    buf[0] = '\0';
    ready  = false;
  }

protected:
  // Called by the library on each key press with the HID keycode and modifier.
  // OemToAscii() converts HID keycode + modifier to an ASCII character.
  // 0x28 is the HID Enter keycode, which signals end of barcode transmission.
  void OnKeyDown(uint8_t mod, uint8_t key) override {
    if (key == 0x28) {  // Enter
      buf[len] = '\0';
      ready    = true;
      return;
    }
    uint8_t c = OemToAscii(mod, key);
    if (c == 0) return;  // non-printable; ignore
    if (len < 31) {
      buf[len++] = (char)c;
    }
  }
};

BarcodeParser barcodeParser;

// =============================================================================
// Barcode -> Chromebook Lookup Table
// =============================================================================

// Maps each Chromebook barcode string to its cart slot number (1-30).
// Slots 1 and 7 have confirmed real barcodes. All others are placeholders
// that will never match a real scan -- safe to leave until barcodes are known.
//
// HOW TO UPDATE:
//   1. Scan the Chromebook and read the string from Serial Monitor.
//   2. Replace the matching "CB_##" placeholder with that string.
//   3. Re-upload this sketch.
struct CBEntry {
  const char* barcode;
  int         cbNumber;
};

const CBEntry cbTable[] = {
  { "5CG0316P3P", 1  },  // real
  { "CB_02",      2  },  // placeholder
  { "CB_03",      3  },  // placeholder
  { "CB_04",      4  },  // placeholder
  { "CB_05",      5  },  // placeholder
  { "CB_06",      6  },  // placeholder
  { "1H85392GMX", 7  },  // real
  { "CB_08",      8  },  // placeholder
  { "CB_09",      9  },  // placeholder
  { "CB_10",      10 },  // placeholder
  { "CB_11",      11 },  // placeholder
  { "CB_12",      12 },  // placeholder
  { "CB_13",      13 },  // placeholder
  { "CB_14",      14 },  // placeholder
  { "CB_15",      15 },  // placeholder
  { "CB_16",      16 },  // placeholder
  { "CB_17",      17 },  // placeholder
  { "CB_18",      18 },  // placeholder
  { "CB_19",      19 },  // placeholder
  { "CB_20",      20 },  // placeholder
  { "CB_21",      21 },  // placeholder
  { "CB_22",      22 },  // placeholder
  { "CB_23",      23 },  // placeholder
  { "CB_24",      24 },  // placeholder
  { "CB_25",      25 },  // placeholder
  { "CB_26",      26 },  // placeholder
  { "CB_27",      27 },  // placeholder
  { "CB_28",      28 },  // placeholder
  { "CB_29",      29 },  // placeholder
  { "CB_30",      30 },  // placeholder
};
const int CB_TABLE_SIZE = sizeof(cbTable) / sizeof(cbTable[0]);

// Returns the cart slot number for the given barcode, or -1 if not found.
int lookupCBNumber(const char* barcode) {
  for (int i = 0; i < CB_TABLE_SIZE; i++) {
    if (strcmp(cbTable[i].barcode, barcode) == 0) {
      return cbTable[i].cbNumber;
    }
  }
  return -1;
}

// =============================================================================
// State Machine
// =============================================================================

// Prefixed with S_ to avoid collision with the Keypad library's KeyState enum.
enum CartState {
  S_IDLE,                    // waiting for first keypress or * for admin
  S_ENTERING_STUDENT_NUMBER, // student typing their 9-digit number
  S_WAITING_FOR_BARCODE_OUT, // student scanning Chromebook barcode to sign out
  S_WAITING_FOR_BARCODE_IN,  // student scanning Chromebook barcode to sign in
  S_SIGN_OUT_SUCCESS,        // confirmation shown for 3s then -> IDLE
  S_SIGN_IN_SUCCESS,         // confirmation shown for 3s then -> IDLE
  S_ERROR_DISPLAY,           // error shown for 3s then -> IDLE
  S_WAITING_FOR_FINGERPRINT, // admin flow: waiting for finger on sensor
  S_ADMIN_MENU,              // admin flow: 1=mode 2=bulk-in 3=bulk-out *=back
  S_BULK_CONFIRM,            // admin flow: confirm bulk sign-out
  S_BULK_COMPLETE,           // admin flow: bulk sign-out done, shown for 3s
  S_BULK_IN_CONFIRM,         // admin flow: confirm bulk sign-in
  S_BULK_IN_COMPLETE         // admin flow: bulk sign-in done, shown for 3s
};

CartState currentState = S_IDLE;

// =============================================================================
// Data
// =============================================================================

// Checkout records: index = CB number - 1, value = student number (0 = free).
// long required: 9-digit student numbers overflow Arduino's 16-bit int.
const int MAX_CHROMEBOOKS = 30;
long checkoutRecords[MAX_CHROMEBOOKS];

// EEPROM layout:
//   Bytes   0-119: checkoutRecords (30 longs x 4 bytes each)
//   Bytes 120-123: magic number
//   Byte    124:   cartMode
const int  EEPROM_BASE_ADDR      = 0;
const int  EEPROM_MAGIC_ADDR     = MAX_CHROMEBOOKS * sizeof(long);  // = 120
const long EEPROM_MAGIC          = 12345678L;
const int  EEPROM_CART_MODE_ADDR = EEPROM_MAGIC_ADDR + sizeof(long);  // = 124

// 0 = INDIVIDUAL: per-student scan in/out, bulk ops blocked.
// 1 = BULK: admin bulk ops only, student flow blocked.
byte cartMode = 0;

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
// Admin Fingerprint Lookup Table
// =============================================================================

// Each admin enrolled at multiple angles across separate slot IDs.
// All slot IDs for the same person map to the same adminNumber.
// Add one row per slot ID, then re-upload.
struct AdminEntry {
  uint8_t fingerID;
  long    adminNumber;
};

const AdminEntry adminTable[] = {
  { 1, 100000001L },  // Staff A - angle 1
  { 2, 100000001L },  // Staff A - angle 2
  { 3, 100000001L },  // Staff A - angle 3
  { 4, 100000002L },  // Staff B - angle 1
  { 5, 100000002L },  // Staff B - angle 2
  { 6, 100000002L },  // Staff B - angle 3
  { 7, 100000003L },  // Staff C - angle 1
  { 8, 100000003L },  // Staff C - angle 2
  { 9, 100000003L },  // Staff C - angle 3
};
const int ADMIN_TABLE_SIZE = sizeof(adminTable) / sizeof(adminTable[0]);

long lookupAdminNumber(uint8_t fpID) {
  for (int i = 0; i < ADMIN_TABLE_SIZE; i++) {
    if (adminTable[i].fingerID == fpID) {
      return adminTable[i].adminNumber;
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
    Serial.println(F("Fingerprint sensor not found - admin mode unavailable."));
  }

  if (Usb.Init() == -1) {
    Serial.println(F("USB shield init failed - barcode scanner unavailable."));
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
  // Service the USB host stack every iteration so HID reports are never missed.
  Usb.Task();

  char key = keypad.getKey();

  switch (currentState) {

    case S_IDLE:
      if (key && key != '*' && key != '#') {
        enterState(S_ENTERING_STUDENT_NUMBER);
        // Capture first digit AFTER enterState() clears inputBuffer.
        inputBuffer[0] = key;
        inputBuffer[1] = '\0';
        updateLCDInput();
      } else if (key == '*') {
        enterState(S_WAITING_FOR_FINGERPRINT);
      }
      break;

    case S_ENTERING_STUDENT_NUMBER:
      if (millis() - stateEnteredAt >= INPUT_TIMEOUT_MS) {
        enterState(S_IDLE);
        break;
      }
      handleStudentNumberInput(key);
      break;

    case S_WAITING_FOR_BARCODE_OUT:
    case S_WAITING_FOR_BARCODE_IN:
      if (millis() - stateEnteredAt >= INPUT_TIMEOUT_MS) {
        enterState(S_IDLE);
        break;
      }
      if (key == '*') {
        enterState(S_IDLE);
        break;
      }
      handleBarcodeInput();
      break;

    case S_ERROR_DISPLAY:
    case S_SIGN_OUT_SUCCESS:
    case S_SIGN_IN_SUCCESS:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) {
        enterState(S_IDLE);
      }
      break;

    case S_WAITING_FOR_FINGERPRINT:
      if (key == '*') {
        enterState(S_IDLE);
        break;
      }
      handleFingerprintInput();
      break;

    case S_ADMIN_MENU:
      if (key == '1') {
        cartMode = 1 - cartMode;
        saveCartMode();
        Serial.print(F("Cart mode set to: "));
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
      if (key == '#') {
        processBulkSignOut();
      } else if (key == '*') {
        enterState(S_ADMIN_MENU);
      }
      break;

    case S_BULK_COMPLETE:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) {
        enterState(S_IDLE);
      }
      break;

    case S_BULK_IN_CONFIRM:
      if (key == '#') {
        processBulkSignIn();
      } else if (key == '*') {
        enterState(S_ADMIN_MENU);
      }
      break;

    case S_BULK_IN_COMPLETE:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) {
        enterState(S_IDLE);
      }
      break;

    default:
      break;
  }
}

// =============================================================================
// Input Handlers
// =============================================================================

// Accumulates keypad digits until STUDENT_NUMBER_LENGTH digits entered, then
// calls checkOpenRecord(). * cancels to idle at any point.
void handleStudentNumberInput(char key) {
  if (!key) return;

  if (key == '*') {
    enterState(S_IDLE);
    return;
  }

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

// Called every loop tick while in a barcode-wait state.
// Does nothing until BarcodeParser signals a complete barcode.
// Looks up the CB number, sets currentCN, and calls confirmSignOut/In().
void handleBarcodeInput() {
  if (!barcodeParser.ready) return;

  int cbNum = lookupCBNumber(barcodeParser.buf);
  Serial.print(F("Barcode scanned: "));
  Serial.print(barcodeParser.buf);
  Serial.print(F(" -> CB "));
  Serial.println(cbNum);
  barcodeParser.reset();

  if (cbNum == -1) {
    showError("Unknown barcode");
    return;
  }

  // Set currentCN as a string for the success screen display.
  itoa(cbNum, currentCN, 10);

  if (currentState == S_WAITING_FOR_BARCODE_OUT) {
    confirmSignOut();
  } else {
    confirmSignIn();
  }
}

// Polls the fingerprint sensor once per loop tick. On a confident match,
// resolves admin number via adminTable[] and enters S_ADMIN_MENU.
void handleFingerprintInput() {
  if (millis() - stateEnteredAt >= FINGERPRINT_TIMEOUT_MS) {
    showError("Scan timeout");
    return;
  }

  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) return;
  if (p != FINGERPRINT_OK) { showError("Sensor error"); return; }

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) { showError("Image error"); return; }

  p = finger.fingerSearch();
  if (p == FINGERPRINT_OK && finger.confidence >= 30) {
    long adminNum = lookupAdminNumber(finger.fingerID);
    if (adminNum == 0) {
      Serial.print(F("Fingerprint ID "));
      Serial.print(finger.fingerID);
      Serial.println(F(" not in admin table."));
      showError("Not registered");
      return;
    }
    currentAdminNum = adminNum;
    Serial.print(F("Admin matched. FP ID: "));
    Serial.print(finger.fingerID);
    Serial.print(F(" -> Admin: "));
    Serial.println(currentAdminNum);
    enterState(S_ADMIN_MENU);
  } else {
    showError("Access denied");
  }
}

// =============================================================================
// Business Logic
// =============================================================================

// Determines sign-out vs sign-in from the student's checkout record and
// routes to the appropriate barcode-wait state.
void checkOpenRecord() {
  if (cartMode == 1) {
    showError("Bulk cart only");
    return;
  }

  long studentNum = strtol(currentStudentNumber, NULL, 10);
  int openCN = -1;

  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == studentNum) {
      openCN = i + 1;
      break;
    }
  }

  if (openCN == -1) {
    enterState(S_WAITING_FOR_BARCODE_OUT);
  } else {
    enterState(S_WAITING_FOR_BARCODE_IN);
  }
}

// Assigns studentNum to the CB slot identified by the barcode scan.
// Fails if the slot is out of range or already taken.
void confirmSignOut() {
  int cn = atoi(currentCN);
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  if (cn < 1 || cn > MAX_CHROMEBOOKS) { showError("Invalid CB #"); return; }
  if (checkoutRecords[cn - 1] != 0)   { showError("CB unavailable"); return; }

  checkoutRecords[cn - 1] = studentNum;
  saveRecord(cn - 1);

  Serial.print(F("Signed out: Student "));
  Serial.print(studentNum);
  Serial.print(F(" -> CB "));
  Serial.println(cn);

  enterState(S_SIGN_OUT_SUCCESS);
}

// Clears the CB slot if the scanned barcode matches the student's open record.
void confirmSignIn() {
  int cn = atoi(currentCN);
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  if (cn < 1 || cn > MAX_CHROMEBOOKS)          { showError("Invalid CB #"); return; }
  if (checkoutRecords[cn - 1] != studentNum)   { showError("No match found"); return; }

  checkoutRecords[cn - 1] = 0;
  saveRecord(cn - 1);

  Serial.print(F("Signed in: CB "));
  Serial.print(cn);
  Serial.print(F(" from Student "));
  Serial.println(studentNum);

  enterState(S_SIGN_IN_SUCCESS);
}

// Assigns admin number to every free CB slot. Blocked on individual-mode carts.
void processBulkSignOut() {
  if (cartMode == 0) { showError("Individ. cart"); return; }

  long adminNum = currentAdminNum;
  int count = 0;

  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == 0) {
      checkoutRecords[i] = adminNum;
      saveRecord(i);
      count++;
    }
  }

  lastBulkCount = count;
  Serial.print(F("Bulk sign-out by admin "));
  Serial.print(adminNum);
  Serial.print(F(": "));
  Serial.print(count);
  Serial.println(F(" CBs signed out."));

  enterState(S_BULK_COMPLETE);
}

// Clears every CB slot assigned to admin number. Blocked on individual-mode carts.
void processBulkSignIn() {
  if (cartMode == 0) { showError("Individ. cart"); return; }

  long adminNum = currentAdminNum;
  int count = 0;

  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == adminNum) {
      checkoutRecords[i] = 0;
      saveRecord(i);
      count++;
    }
  }

  if (count == 0) { showError("No CBs found"); return; }

  lastBulkCount = count;
  Serial.print(F("Bulk sign-in by admin "));
  Serial.print(adminNum);
  Serial.print(F(": "));
  Serial.print(count);
  Serial.println(F(" CBs returned."));

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

void enterState(int newState) {
  currentState   = (CartState)newState;
  stateEnteredAt = millis();
  inputBuffer[0] = '\0';

  // Flush stale bytes from fingerprint sensor SoftwareSerial RX buffer.
  if (newState == S_WAITING_FOR_FINGERPRINT) {
    while (fingerprintSerial.available()) fingerprintSerial.read();
  }

  // Reset barcode parser so a leftover scan cannot auto-complete a new session.
  if (newState == S_WAITING_FOR_BARCODE_OUT || newState == S_WAITING_FOR_BARCODE_IN) {
    barcodeParser.reset();
  }

  updateLCD();
}

// =============================================================================
// Display
// =============================================================================

// Colors: green = idle/input/success, orange = sign-out, blue = sign-in,
//         red = error, purple = admin flow.
void updateLCD() {
  lcd.clear();
  switch (currentState) {

    case S_IDLE:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      if (cartMode == 1) {
        lcd.print(F("Bulk cart"));
        lcd.setCursor(0, 1);
        lcd.print(F("Admin accs only"));
      } else {
        lcd.print(F("Enter student #"));
      }
      break;

    case S_ENTERING_STUDENT_NUMBER:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Student #:"));
      lcd.setCursor(0, 1);
      lcd.print(inputBuffer);
      break;

    case S_WAITING_FOR_BARCODE_OUT:
      lcd.setRGB(255, 165, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Sign OUT"));
      lcd.setCursor(0, 1);
      lcd.print(F("Scan barcode..."));
      break;

    case S_WAITING_FOR_BARCODE_IN:
      lcd.setRGB(0, 100, 255);
      lcd.setCursor(0, 0);
      lcd.print(F("Sign IN"));
      lcd.setCursor(0, 1);
      lcd.print(F("Scan barcode..."));
      break;

    case S_SIGN_OUT_SUCCESS:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Signed OUT!"));
      lcd.setCursor(0, 1);
      lcd.print(F("CB #"));
      lcd.print(currentCN);
      break;

    case S_SIGN_IN_SUCCESS:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Signed IN!"));
      lcd.setCursor(0, 1);
      lcd.print(F("CB #"));
      lcd.print(currentCN);
      break;

    case S_ERROR_DISPLAY:
      lcd.setRGB(255, 0, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Error:"));
      lcd.setCursor(0, 1);
      lcd.print(errorMessage);
      break;

    case S_WAITING_FOR_FINGERPRINT:
      lcd.setRGB(128, 0, 128);
      lcd.setCursor(0, 0);
      lcd.print(F("Admin: scan"));
      lcd.setCursor(0, 1);
      lcd.print(F("fingerprint..."));
      break;

    case S_ADMIN_MENU:
      lcd.setRGB(128, 0, 128);
      lcd.setCursor(0, 0);
      if (cartMode == 1) {
        lcd.print(F("ADMIN [BULK]   "));
      } else {
        lcd.print(F("ADMIN [INDIVID]"));
      }
      lcd.setCursor(0, 1);
      lcd.print(F("1:Md 2:In 3:Out"));
      break;

    case S_BULK_CONFIRM:
      lcd.setRGB(255, 165, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Sign out ALL?"));
      lcd.setCursor(0, 1);
      lcd.print(F("#:Yes    *:No"));
      break;

    case S_BULK_COMPLETE:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Bulk OUT done!"));
      lcd.setCursor(0, 1);
      lcd.print(lastBulkCount);
      lcd.print(F(" CBs signed out"));
      break;

    case S_BULK_IN_CONFIRM:
      lcd.setRGB(255, 165, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Sign in ALL?"));
      lcd.setCursor(0, 1);
      lcd.print(F("#:Yes    *:No"));
      break;

    case S_BULK_IN_COMPLETE:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Bulk IN done!"));
      lcd.setCursor(0, 1);
      lcd.print(lastBulkCount);
      lcd.print(F(" CBs returned"));
      break;

    default:
      break;
  }
}

// Refreshes only line 2 during student number entry to avoid full-screen flicker.
void updateLCDInput() {
  lcd.setCursor(0, 1);
  lcd.print(F("                "));
  lcd.setCursor(0, 1);
  lcd.print(inputBuffer);
}
