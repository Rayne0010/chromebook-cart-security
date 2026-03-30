/*
 * Chromebook Cart Security System
 * Cart Arduino
 *
 * Responsibilities:
 *   - 12-digit keypad input for student number + Chromebook number
 *   - Sign-out: associate student number with Chromebook number
 *   - Sign-in: clear association for returned Chromebook
 *   - LCD display for user prompts and feedback
 *   - Fingerprint sensor for admin access and bulk cart sign-out/sign-in
 *
 * States (Primary Scope):
 *   S_IDLE -> S_ENTERING_STUDENT_NUMBER -> VALIDATING_STUDENT
 *   -> CHECK_OPEN_RECORD -> S_ENTERING_CN_OUT or S_ENTERING_CN_IN
 *   -> CONFIRM -> SUCCESS / ERROR
 *
 * States (Secondary Scope - Admin):
 *   S_IDLE --(*)--> S_WAITING_FOR_FINGERPRINT
 *   -> S_ENTERING_ADMIN_NUMBER -> S_ADMIN_MENU
 *   -> S_BULK_CONFIRM -> S_BULK_COMPLETE
 *   -> S_BULK_IN_CONFIRM -> S_BULK_IN_COMPLETE
 *
 * Fix notes:
 *   - Removed recursive enterState() calls from inside updateLCD().
 *     Previously, SIGN_OUT and SIGN_IN cases in updateLCD() called
 *     enterState(), which called updateLCD() again. Now checkOpenRecord()
 *     jumps directly to S_ENTERING_CN_OUT or S_ENTERING_CN_IN, skipping
 *     those intermediate states entirely.
 *   - First keypress in S_IDLE is now captured after enterState() to avoid
 *     being wiped by the inputBuffer reset inside enterState().
 *   - checkoutRecords[] changed from int to long, and student number parsing
 *     changed to strtol() since Arduino's String class has no .toLong() method.
 *   - Fingerprint confidence threshold lowered to 30 for improved reliability.
 *   - S_BULK_COMPLETE LCD message corrected to reflect that only free slots
 *     are assigned, not all slots, and shortened to fit 16-char display.
 *   - checkoutRecords[] now persisted to EEPROM so data survives power cycles.
 *     A magic number at a fixed EEPROM address detects first-boot and
 *     initializes all records to 0.
 *   - SoftwareSerial buffer is flushed when entering S_WAITING_FOR_FINGERPRINT
 *     to prevent stale bytes from a previous scan causing fingerSearch() to fail.
 *   - Admin number is now entered after fingerprint verification and stored as
 *     the owner of bulk-signed-out CBs, replacing the hardcoded sentinel value.
 *   - Bulk sign-in added: clears all CBs assigned to the current admin number.
 *   - processBulkSignIn() now shows an error if no CBs match the admin number,
 *     preventing a silent success with 0 CBs cleared.
 *   - String objects replaced with fixed char[] arrays to eliminate heap
 *     fragmentation and reduce RAM usage.
 *   - All string literals wrapped in F() macro to store them in flash instead
 *     of RAM.
 *   - Input timeout added: S_ENTERING_STUDENT_NUMBER, S_ENTERING_CN_OUT, and
 *     S_ENTERING_CN_IN auto-reset to S_IDLE after INPUT_TIMEOUT_MS of inactivity.
 *   - Bulk op count now displayed on LCD line 2 of S_BULK_COMPLETE and
 *     S_BULK_IN_COMPLETE so the admin can confirm how many CBs were processed.
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

#include <Keypad.h>
#include <Wire.h>
#include <rgb_lcd.h>
#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>
#include <EEPROM.h>

// --- Keypad Setup ---
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

// --- LCD Setup ---
// Grove LCD RGB Backlight - no I2C address needed, handled by library
rgb_lcd lcd;

// --- Fingerprint Sensor Setup ---
// RX = pin 9, TX = pin 10
SoftwareSerial fingerprintSerial(9, 10);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&fingerprintSerial);

// --- State Machine ---
// Prefixed with S_ to avoid collision with Keypad library's KeyState enum,
// which defines its own IDLE value.
enum State {
  S_IDLE,
  S_ENTERING_STUDENT_NUMBER,
  S_ENTERING_CN_OUT,
  S_ENTERING_CN_IN,
  S_SIGN_OUT_SUCCESS,
  S_SIGN_IN_SUCCESS,
  S_ERROR_DISPLAY,
  S_WAITING_FOR_FINGERPRINT,
  S_ENTERING_ADMIN_NUMBER,
  S_ADMIN_MENU,
  S_BULK_CONFIRM,
  S_BULK_COMPLETE,
  S_BULK_IN_CONFIRM,
  S_BULK_IN_COMPLETE
};

State currentState = S_IDLE;

// --- Data ---
// Records persisted to EEPROM: index = Chromebook number - 1, value = student number (0 = available)
const int MAX_CHROMEBOOKS = 30;
long checkoutRecords[MAX_CHROMEBOOKS];

// EEPROM layout:
//   Bytes 0-119:  checkoutRecords (30 x 4 bytes each)
//   Bytes 120-123: magic number (detects whether EEPROM has been initialized)
const int EEPROM_BASE_ADDR  = 0;
const int EEPROM_MAGIC_ADDR = MAX_CHROMEBOOKS * sizeof(long);  // 120
const long EEPROM_MAGIC     = 12345678L;

const int STUDENT_NUMBER_LENGTH = 9;
const int ADMIN_NUMBER_LENGTH   = 9;
const int CN_LENGTH = 2;

// Fingerprint scan will time out and return to idle after this duration
const int FINGERPRINT_TIMEOUT_MS = 10000;

// Keypad input states will time out and return to idle after this duration
const int INPUT_TIMEOUT_MS = 15000;

// Fixed char arrays replace String objects to eliminate heap fragmentation
char inputBuffer[10]          = "";  // max 9 digits + null
char currentStudentNumber[10] = "";
char currentAdminNumber[10]   = "";
char currentCN[3]             = "";  // max 2 digits + null
char errorMessage[17]         = "";  // max 16 chars + null

unsigned long stateEnteredAt = 0;
const int MESSAGE_DISPLAY_DURATION_MS = 3000;

// Stores the count from the last bulk operation for LCD display
int lastBulkCount = 0;

// --- EEPROM Helpers ---

void saveRecord(int index) {
  EEPROM.put(EEPROM_BASE_ADDR + index * sizeof(long), checkoutRecords[index]);
}

void loadRecords() {
  long magic;
  EEPROM.get(EEPROM_MAGIC_ADDR, magic);
  if (magic != EEPROM_MAGIC) {
    // First boot: initialize all records to 0 and write magic number
    for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
      checkoutRecords[i] = 0;
      EEPROM.put(EEPROM_BASE_ADDR + i * sizeof(long), checkoutRecords[i]);
    }
    EEPROM.put(EEPROM_MAGIC_ADDR, EEPROM_MAGIC);
    Serial.println(F("EEPROM initialized."));
  } else {
    for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
      EEPROM.get(EEPROM_BASE_ADDR + i * sizeof(long), checkoutRecords[i]);
    }
    Serial.println(F("Records loaded from EEPROM."));
  }
}

// --- Setup ---

void setup() {
  Serial.begin(9600);
  lcd.begin(16, 2);
  lcd.setRGB(0, 255, 0);      // green backlight by default

  loadRecords();

  finger.begin(57600);
  if (finger.verifyPassword()) {
    Serial.println(F("Fingerprint sensor found."));
  } else {
    Serial.println(F("Fingerprint sensor not found - admin mode unavailable."));
  }

  enterState(S_IDLE);
  Serial.println(F("Cart system ready."));
}

// --- Main Loop ---

void loop() {
  char key = keypad.getKey();

  switch (currentState) {
    case S_IDLE:
      if (key && key != '*' && key != '#') {
        enterState(S_ENTERING_STUDENT_NUMBER);
        inputBuffer[0] = key;   // set AFTER enterState clears it
        inputBuffer[1] = '\0';
        updateLCDInput();       // show first digit on screen
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

    case S_ENTERING_CN_OUT:
    case S_ENTERING_CN_IN:
      if (millis() - stateEnteredAt >= INPUT_TIMEOUT_MS) {
        enterState(S_IDLE);
        break;
      }
      handleCNInput(key);
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

    case S_ENTERING_ADMIN_NUMBER:
      handleAdminNumberInput(key);
      break;

    case S_ADMIN_MENU:
      if (key == '2') {
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

// --- Input Handlers ---

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

void handleAdminNumberInput(char key) {
  if (!key) return;

  if (key == '*') {
    enterState(S_IDLE);
    return;
  }

  if (key != '#') {
    int len = strlen(inputBuffer);
    if (len < ADMIN_NUMBER_LENGTH) {
      inputBuffer[len]     = key;
      inputBuffer[len + 1] = '\0';
      updateLCDInput();
    }
  }

  if (strlen(inputBuffer) == ADMIN_NUMBER_LENGTH) {
    strncpy(currentAdminNumber, inputBuffer, 10);
    inputBuffer[0] = '\0';
    Serial.print(F("Admin number entered: "));
    Serial.println(currentAdminNumber);
    enterState(S_ADMIN_MENU);
  }
}

void handleCNInput(char key) {
  if (!key) return;

  if (key == '*') {
    enterState(S_IDLE);
    return;
  }

  if (key == '#') {
    if (strlen(inputBuffer) > 0) {
      strncpy(currentCN, inputBuffer, 3);
      inputBuffer[0] = '\0';
      if (currentState == S_ENTERING_CN_OUT) {
        confirmSignOut();
      } else {
        confirmSignIn();
      }
    }
    return;
  }

  int len = strlen(inputBuffer);
  if (len < CN_LENGTH) {
    inputBuffer[len]     = key;
    inputBuffer[len + 1] = '\0';
    updateLCDInput();
  }
}

void handleFingerprintInput() {
  if (millis() - stateEnteredAt >= FINGERPRINT_TIMEOUT_MS) {
    showError("Scan timeout");
    return;
  }

  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) return;  // no finger yet, keep waiting
  if (p != FINGERPRINT_OK) {
    showError("Sensor error");
    return;
  }

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) {
    showError("Image error");
    return;
  }

  p = finger.fingerSearch();
  if (p == FINGERPRINT_OK && finger.confidence >= 30) {
    Serial.print(F("Admin fingerprint matched. ID: "));
    Serial.println(finger.fingerID);
    enterState(S_ENTERING_ADMIN_NUMBER);
  } else {
    showError("Access denied");
  }
}

// --- Business Logic ---

void checkOpenRecord() {
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  int openCN = -1;
  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == studentNum) {
      openCN = i + 1;
      break;
    }
  }

  if (openCN == -1) {
    // No open record: student is signing out a Chromebook
    enterState(S_ENTERING_CN_OUT);
  } else {
    // Open record found: student is returning their Chromebook
    itoa(openCN, currentCN, 10);
    enterState(S_ENTERING_CN_IN);
  }
}

void confirmSignOut() {
  int cn = atoi(currentCN);
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  if (cn < 1 || cn > MAX_CHROMEBOOKS) {
    showError("Invalid CB #");
    return;
  }

  if (checkoutRecords[cn - 1] != 0) {
    showError("CB unavailable");
    return;
  }

  checkoutRecords[cn - 1] = studentNum;
  saveRecord(cn - 1);
  Serial.print(F("Signed out: Student "));
  Serial.print(studentNum);
  Serial.print(F(" -> CB "));
  Serial.println(cn);

  enterState(S_SIGN_OUT_SUCCESS);
}

void confirmSignIn() {
  int cn = atoi(currentCN);
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  if (cn < 1 || cn > MAX_CHROMEBOOKS) {
    showError("Invalid CB #");
    return;
  }

  if (checkoutRecords[cn - 1] != studentNum) {
    showError("No match found");
    return;
  }

  checkoutRecords[cn - 1] = 0;
  saveRecord(cn - 1);
  Serial.print(F("Signed in: CB "));
  Serial.print(cn);
  Serial.print(F(" from Student "));
  Serial.println(studentNum);

  enterState(S_SIGN_IN_SUCCESS);
}

void processBulkSignOut() {
  long adminNum = strtol(currentAdminNumber, NULL, 10);
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

void processBulkSignIn() {
  long adminNum = strtol(currentAdminNumber, NULL, 10);
  int count = 0;
  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == adminNum) {
      checkoutRecords[i] = 0;
      saveRecord(i);
      count++;
    }
  }
  if (count == 0) {
    showError("No CBs found");
    return;
  }
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

// --- State Transition ---

void enterState(State newState) {
  currentState = newState;
  stateEnteredAt = millis();
  inputBuffer[0] = '\0';
  // Flush stale SoftwareSerial bytes so fingerSearch() starts clean each time
  if (newState == S_WAITING_FOR_FINGERPRINT) {
    while (fingerprintSerial.available()) fingerprintSerial.read();
  }
  updateLCD();
}

// --- Display ---

void updateLCD() {
  lcd.clear();
  switch (currentState) {
    case S_IDLE:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Enter student #"));
      break;

    case S_ENTERING_STUDENT_NUMBER:
      lcd.setRGB(0, 255, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Student #:"));
      lcd.setCursor(0, 1);
      lcd.print(inputBuffer);
      break;

    case S_ENTERING_CN_OUT:
      lcd.setRGB(255, 165, 0);
      lcd.setCursor(0, 0);
      lcd.print(F("Sign OUT"));
      lcd.setCursor(0, 1);
      lcd.print(F("Enter CB #:"));
      break;

    case S_ENTERING_CN_IN:
      lcd.setRGB(0, 100, 255);
      lcd.setCursor(0, 0);
      lcd.print(F("Sign IN"));
      lcd.setCursor(0, 1);
      lcd.print(F("Enter CB #:"));
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

    case S_ENTERING_ADMIN_NUMBER:
      lcd.setRGB(128, 0, 128);
      lcd.setCursor(0, 0);
      lcd.print(F("Admin #:"));
      lcd.setCursor(0, 1);
      lcd.print(inputBuffer);
      break;

    case S_ADMIN_MENU:
      lcd.setRGB(128, 0, 128);
      lcd.setCursor(0, 0);
      lcd.print(F("ADMIN MENU"));
      lcd.setCursor(0, 1);
      lcd.print(F("2:In 3:Out *:Bk"));
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

void updateLCDInput() {
  lcd.setCursor(0, 1);
  lcd.print(F("                "));
  lcd.setCursor(0, 1);
  lcd.print(inputBuffer);
}
