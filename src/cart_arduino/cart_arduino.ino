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
 *   - USB barcode scanner: confirms correct CB taken after sign-out
 *
 * States (Primary Scope):
 *   S_IDLE -> S_ENTERING_STUDENT_NUMBER
 *   -> S_ENTERING_CN_OUT or S_ENTERING_CN_IN
 *   -> S_SCAN_TIMER_ACTIVE (barcode window) -> S_SIGN_OUT_SUCCESS / S_BARCODE_ALARM
 *   -> S_SIGN_IN_SUCCESS / S_ERROR_DISPLAY -> S_IDLE
 *
 * States (Secondary Scope - Admin):
 *   S_IDLE --(*)--> S_WAITING_FOR_FINGERPRINT
 *   -> S_ADMIN_MENU
 *   -> S_BULK_CONFIRM -> S_BULK_COMPLETE -> S_IDLE
 *   -> S_BULK_IN_CONFIRM -> S_BULK_IN_COMPLETE -> S_IDLE
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
 *     changed to strtol() since Arduino's int is 16-bit and overflows on
 *     9-digit student numbers.
 *   - Fingerprint confidence threshold lowered to 30 for improved reliability
 *     with consumer-grade sensors.
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
 *   - Input timeout added: S_ENTERING_STUDENT_NUMBER, S_ENTERING_CN_OUT,
 *     and S_ENTERING_CN_IN auto-reset to S_IDLE after INPUT_TIMEOUT_MS
 *     of inactivity.
 *   - Bulk op count now displayed on LCD line 2 of S_BULK_COMPLETE and
 *     S_BULK_IN_COMPLETE so the admin can confirm how many CBs were processed.
 *   - Dead itoa() pre-fill of currentCN removed from checkOpenRecord().
 *     handleCNInput() always overwrites currentCN from inputBuffer before
 *     calling confirmSignIn(), so the pre-fill had no effect.
 *   - handleCNInput() now shows an "Enter CB #" error if # is pressed while
 *     the input buffer is empty, instead of silently ignoring the keypress.
 *   - Cart mode added: each cart is either INDIVIDUAL (per-student sign-out;
 *     bulk ops blocked) or BULK (only admin bulk sign-out/in; student
 *     individual sign-out blocked with "Bulk cart only" error).
 *     Mode is stored in EEPROM at byte 124, defaults to INDIVIDUAL on first
 *     boot, and is toggled by pressing 1 in the admin menu. The admin menu
 *     LCD now shows the current mode on line 0 and includes 1:Md in the key
 *     guide on line 1.
 *   - Admin number entry step removed. fingerID returned by fingerSearch() is
 *     now looked up in a compile-time adminTable[] that maps each enrolled
 *     slot ID to its owner's admin number. Multiple slot IDs can share the
 *     same admin number to cover multiple enrollment angles. If the matched
 *     fingerID is not in the table, access is denied. S_ENTERING_ADMIN_NUMBER
 *     and handleAdminNumberInput() have been removed.
 *   - USB barcode scanner integration added (secondary scope).
 *     USB Host Shield (MAX3421E, ARCELI) with USB Host Shield Library 2.0.
 *     Barcode scanner enumerates as a HID keyboard device. After a successful
 *     student sign-out, the system enters S_SCAN_TIMER_ACTIVE and waits up to
 *     SCAN_TIMEOUT_MS for the student to scan the Chromebook barcode.
 *     A valid scan (barcode matches currentCN) advances to S_SIGN_OUT_SUCCESS.
 *     An invalid scan or timeout advances to S_BARCODE_ALARM.
 *     KbdRptParser::OnKeyDown() accumulates HID key events into barcodeBuffer
 *     and sets barcodeReady = true on Enter (HID keycode 0x28).
 *     barcodeBuffer and barcodeReady are reset each time S_SCAN_TIMER_ACTIVE
 *     is entered. Usb.Task() is called every loop iteration regardless of
 *     state so the USB stack stays alive.
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
// USB Barcode Scanner Setup
// =============================================================================

// USB Host Shield (MAX3421E) uses SPI with INT on pin 9, SS on pin 10.
// HIDBoot configures the attached USB device in Boot-protocol keyboard mode,
// which all HID keyboards (including barcode scanners) must support.
USB                                     Usb;
USBHub                                  Hub(&Usb);
HIDBoot<USB_HID_PROTOCOL_KEYBOARD>      HidKeyboard(&Usb);

// barcodeBuffer: accumulates characters received from the scanner.
// Sized for safety; CB numbers are at most 2 digits, but scanners may send
// a longer asset tag string depending on how the barcodes were printed.
// Adjust BARCODE_MAX_LEN and the validation logic in validateBarcode() if your
// barcodes contain more than just the CB number.
const int BARCODE_MAX_LEN = 16;
char      barcodeBuffer[BARCODE_MAX_LEN + 1] = "";
bool      barcodeReady                        = false;

// KbdRptParser: subclass of KeyboardReportParser that accumulates keystrokes
// from the barcode scanner into barcodeBuffer and sets barcodeReady on Enter.
// OnKeyDown() is called by the USB Host Shield library once per key event.
class KbdRptParser : public KeyboardReportParser {
protected:
  void OnKeyDown(uint8_t mod, uint8_t key) override;
};

void KbdRptParser::OnKeyDown(uint8_t mod, uint8_t key) {
  if (key == 0x28) {
    // Enter key: barcode transmission complete.
    barcodeReady = true;
    return;
  }

  // Convert HID keycode to ASCII character using the library helper.
  // OemToAscii handles modifier keys (Shift) and returns 0 for non-printable keys.
  uint8_t c = OemToAscii(mod, key);
  if (c == 0) return;  // non-printable key; ignore

  int len = strlen(barcodeBuffer);
  if (len < BARCODE_MAX_LEN) {
    barcodeBuffer[len]     = (char)c;
    barcodeBuffer[len + 1] = '\0';
  }
  // If the buffer is full, additional characters are silently dropped.
  // A real barcode should never overflow BARCODE_MAX_LEN.
}

KbdRptParser BarcodeParser;

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
// Templates are stored on the sensor's onboard flash, not in Arduino RAM.
SoftwareSerial fingerprintSerial(A0, A1);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&fingerprintSerial);

// =============================================================================
// State Machine
// =============================================================================

// Prefixed with S_ to avoid collision with the Keypad library's KeyState enum,
// which defines its own IDLE constant.
enum State {
  S_IDLE,                    // waiting for first keypress or * for admin
  S_ENTERING_STUDENT_NUMBER, // student typing their 9-digit number
  S_ENTERING_CN_OUT,         // student typing Chromebook number to sign out
  S_ENTERING_CN_IN,          // student typing Chromebook number to sign in
  S_SCAN_TIMER_ACTIVE,       // barcode window: student must scan CB within timeout
  S_BARCODE_ALARM,           // barcode scan timed out or barcode did not match
  S_SIGN_OUT_SUCCESS,        // confirmation message shown for 3s then -> IDLE
  S_SIGN_IN_SUCCESS,         // confirmation message shown for 3s then -> IDLE
  S_ERROR_DISPLAY,           // error message shown for 3s then -> IDLE
  S_WAITING_FOR_FINGERPRINT, // admin flow: waiting for finger on sensor
  S_ADMIN_MENU,              // admin flow: choose bulk-out (3), bulk-in (2), or back (*)
  S_BULK_CONFIRM,            // admin flow: confirm sign-out of entire cart
  S_BULK_COMPLETE,           // admin flow: bulk sign-out done, shown for 3s
  S_BULK_IN_CONFIRM,         // admin flow: confirm sign-in of entire cart
  S_BULK_IN_COMPLETE         // admin flow: bulk sign-in done, shown for 3s
};

State currentState = S_IDLE;

// =============================================================================
// Data
// =============================================================================

// Checkout records: index = Chromebook number - 1, value = student number.
// 0 means the Chromebook is available. Persisted to EEPROM.
// long is required because 9-digit student numbers overflow Arduino's 16-bit int.
const int MAX_CHROMEBOOKS = 30;
long checkoutRecords[MAX_CHROMEBOOKS];

// EEPROM layout:
//   Bytes   0-119: checkoutRecords (30 longs x 4 bytes each)
//   Bytes 120-123: magic number (used to detect whether EEPROM has been
//                  initialized; avoids treating garbage as valid records)
//   Byte    124:   cartMode (0 = individual, 1 = bulk)
const int  EEPROM_BASE_ADDR      = 0;
const int  EEPROM_MAGIC_ADDR     = MAX_CHROMEBOOKS * sizeof(long);  // = 120
const long EEPROM_MAGIC          = 12345678L;
const int  EEPROM_CART_MODE_ADDR = EEPROM_MAGIC_ADDR + sizeof(long);  // = 124

// Cart operating mode, persisted to EEPROM.
// 0 = INDIVIDUAL: students sign CBs in/out one at a time; bulk ops blocked.
// 1 = BULK: only admin bulk sign-out/in allowed; student individual flow blocked.
byte cartMode = 0;

// Input length constraints
const int STUDENT_NUMBER_LENGTH = 9;  // exactly 9 digits
const int CN_LENGTH             = 2;  // Chromebook numbers 1-30 (1 or 2 digits)

// Timeout durations (milliseconds)
const unsigned long FINGERPRINT_TIMEOUT_MS      = 10000;  // 10s to scan finger
const unsigned long INPUT_TIMEOUT_MS            = 15000;  // 15s idle on any input state
const unsigned long MESSAGE_DISPLAY_DURATION_MS = 3000;   // 3s for success/error messages
const unsigned long SCAN_TIMEOUT_MS             = 30000;  // 30s to scan barcode after sign-out

// Fixed-size char arrays replace String objects to avoid heap fragmentation.
// Sizes include the null terminator.
char inputBuffer[10]          = "";  // active typing buffer (max 9 digits + \0)
char currentStudentNumber[10] = "";  // student number confirmed this session
long currentAdminNum          = 0;   // admin number resolved from fingerprint lookup
char currentCN[3]             = "";  // Chromebook number confirmed this session (max 2 digits + \0)
char errorMessage[17]         = "";  // error text for LCD line 2 (max 16 chars + \0)

// Timestamp of when the current state was entered, used for timeouts
unsigned long stateEnteredAt = 0;

// Result count from the most recent bulk operation, shown on the completion screen
int lastBulkCount = 0;

// =============================================================================
// EEPROM Helpers
// =============================================================================

// Write one checkout record to EEPROM at the correct byte offset.
// Called immediately after any change to checkoutRecords[index].
void saveRecord(int index) {
  EEPROM.put(EEPROM_BASE_ADDR + index * sizeof(long), checkoutRecords[index]);
}

// Write the current cartMode byte to EEPROM.
// Called immediately after any admin toggle of cartMode.
void saveCartMode() {
  EEPROM.put(EEPROM_CART_MODE_ADDR, cartMode);
}

// Load all checkout records and cartMode from EEPROM on boot.
// If the magic number is missing (first power-on or after a flash), all records
// are initialized to 0, cartMode is set to INDIVIDUAL (0), and the magic number
// is written so subsequent boots load real data.
void loadRecords() {
  long magic;
  EEPROM.get(EEPROM_MAGIC_ADDR, magic);
  if (magic != EEPROM_MAGIC) {
    // First boot: EEPROM is uninitialized. Zero all records and mark as ready.
    for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
      checkoutRecords[i] = 0;
      EEPROM.put(EEPROM_BASE_ADDR + i * sizeof(long), checkoutRecords[i]);
    }
    cartMode = 0;
    EEPROM.put(EEPROM_CART_MODE_ADDR, cartMode);
    EEPROM.put(EEPROM_MAGIC_ADDR, EEPROM_MAGIC);
    Serial.println(F("EEPROM initialized."));
  } else {
    // Normal boot: load previously saved records and mode into RAM.
    for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
      EEPROM.get(EEPROM_BASE_ADDR + i * sizeof(long), checkoutRecords[i]);
    }
    EEPROM.get(EEPROM_CART_MODE_ADDR, cartMode);
    // Guard against corrupted mode byte (anything other than 0 or 1)
    if (cartMode != 0 && cartMode != 1) cartMode = 0;
    Serial.println(F("Records loaded from EEPROM."));
  }
}

// =============================================================================
// Admin Fingerprint Lookup Table
// =============================================================================

// Maps each enrolled fingerprint slot ID to the corresponding admin number.
// Each admin should be enrolled at multiple angles across separate slot IDs
// to reduce false negatives; all those slot IDs map to the same adminNumber.
//
// HOW TO ADD AN ADMIN:
//   1. Enroll their finger 2-3 times using the enrollment sketch, noting the
//      slot IDs assigned (e.g. 1, 2, 3 for angle variations).
//   2. Add one row per slot ID below, all pointing to the same adminNumber.
//   3. Re-upload this sketch.
//
// fingerID values match the slot IDs written during enrollment (1-indexed).
struct AdminEntry {
  uint8_t fingerID;    // slot ID on the sensor (as returned by fingerSearch())
  long    adminNumber; // 9-digit staff number this fingerID belongs to
};

const AdminEntry adminTable[] = {
  // --- Example admin entries (replace with real data before deployment) ---
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

// Returns the adminNumber for the given fingerID, or 0 if not found.
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

  // LCD: 16 columns, 2 rows. Default backlight is green (idle color).
  lcd.begin(16, 2);
  lcd.setRGB(0, 255, 0);

  loadRecords();

  // Fingerprint sensor communicates at 57600 baud over SoftwareSerial.
  finger.begin(57600);
  if (finger.verifyPassword()) {
    Serial.println(F("Fingerprint sensor found."));
  } else {
    // System still works for student flow; admin mode will be unavailable.
    Serial.println(F("Fingerprint sensor not found - admin mode unavailable."));
  }

  // USB Host Shield initialization. Usb.Init() returns -1 on failure (e.g.,
  // shield not connected or SPI wiring issue). The barcode scanner will not
  // work if init fails, but the rest of the system continues normally.
  if (Usb.Init() == -1) {
    Serial.println(F("USB Host Shield init failed - barcode scanner unavailable."));
  } else {
    Serial.println(F("USB Host Shield ready."));
  }
  // Attach our parser to HID interface 0 (the keyboard boot interface).
  HidKeyboard.SetReportParser(0, &BarcodeParser);

  enterState(S_IDLE);
  Serial.println(F("Cart system ready."));
}

// =============================================================================
// Main Loop
// =============================================================================

void loop() {
  // Drive the USB stack every iteration regardless of current state.
  // Without this call the shield will not enumerate the scanner or deliver
  // key events to BarcodeParser.
  Usb.Task();

  // Poll the keypad once per loop iteration. Returns '\0' if no key is pressed.
  char key = keypad.getKey();

  switch (currentState) {

    case S_IDLE:
      // Any digit starts student number entry. * triggers admin fingerprint flow.
      // # is ignored in idle (no context to submit).
      if (key && key != '*' && key != '#') {
        enterState(S_ENTERING_STUDENT_NUMBER);
        // Capture the first digit AFTER enterState() clears inputBuffer,
        // otherwise enterState() would wipe it immediately.
        inputBuffer[0] = key;
        inputBuffer[1] = '\0';
        updateLCDInput();
      } else if (key == '*') {
        enterState(S_WAITING_FOR_FINGERPRINT);
      }
      break;

    case S_ENTERING_STUDENT_NUMBER:
      // Auto-cancel if no input received within the timeout window.
      if (millis() - stateEnteredAt >= INPUT_TIMEOUT_MS) {
        enterState(S_IDLE);
        break;
      }
      handleStudentNumberInput(key);
      break;

    case S_ENTERING_CN_OUT:
    case S_ENTERING_CN_IN:
      // Auto-cancel if no input received within the timeout window.
      if (millis() - stateEnteredAt >= INPUT_TIMEOUT_MS) {
        enterState(S_IDLE);
        break;
      }
      handleCNInput(key);
      break;

    case S_SCAN_TIMER_ACTIVE:
      // Wait for the barcode scanner to deliver a complete scan (barcodeReady),
      // or time out after SCAN_TIMEOUT_MS and trigger the alarm.
      // * allows an admin to cancel the window (e.g., scanner malfunction).
      if (key == '*') {
        enterState(S_BARCODE_ALARM);
        break;
      }
      if (millis() - stateEnteredAt >= SCAN_TIMEOUT_MS) {
        Serial.println(F("Barcode scan timeout."));
        enterState(S_BARCODE_ALARM);
        break;
      }
      if (barcodeReady) {
        validateBarcode();
      }
      break;

    case S_BARCODE_ALARM:
      // Alarm stays on screen until * is pressed (admin intervention).
      if (key == '*') {
        enterState(S_IDLE);
      }
      break;

    // These states just display a message and auto-return to idle after a delay.
    case S_ERROR_DISPLAY:
    case S_SIGN_OUT_SUCCESS:
    case S_SIGN_IN_SUCCESS:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) {
        enterState(S_IDLE);
      }
      break;

    case S_WAITING_FOR_FINGERPRINT:
      // * cancels and returns to idle; otherwise poll the sensor each loop tick.
      if (key == '*') {
        enterState(S_IDLE);
        break;
      }
      handleFingerprintInput();
      break;

    case S_ADMIN_MENU:
      // 1 = toggle cart mode, 2 = bulk sign-in, 3 = bulk sign-out, * = back to idle
      if (key == '1') {
        cartMode = 1 - cartMode;  // toggle between 0 and 1
        saveCartMode();
        Serial.print(F("Cart mode set to: "));
        Serial.println(cartMode == 1 ? F("BULK") : F("INDIVIDUAL"));
        updateLCD();  // re-render menu to show new mode; don't reset state timer
      } else if (key == '2') {
        enterState(S_BULK_IN_CONFIRM);
      } else if (key == '3') {
        enterState(S_BULK_CONFIRM);
      } else if (key == '*') {
        enterState(S_IDLE);
      }
      break;

    case S_BULK_CONFIRM:
      // # confirms the bulk sign-out; * cancels and returns to admin menu.
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
      // # confirms the bulk sign-in; * cancels and returns to admin menu.
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

// Accumulates keypad digits into inputBuffer until STUDENT_NUMBER_LENGTH is
// reached, then calls checkOpenRecord() to determine sign-out vs sign-in.
// * cancels at any point and returns to idle.
void handleStudentNumberInput(char key) {
  if (!key) return;

  if (key == '*') {
    enterState(S_IDLE);
    return;
  }

  // Accumulate digits (ignore # mid-entry; submission is automatic at 9 digits)
  if (key != '#') {
    int len = strlen(inputBuffer);
    if (len < STUDENT_NUMBER_LENGTH) {
      inputBuffer[len]     = key;
      inputBuffer[len + 1] = '\0';
      updateLCDInput();
    }
  }

  // Auto-submit once 9 digits have been entered
  if (strlen(inputBuffer) == STUDENT_NUMBER_LENGTH) {
    strncpy(currentStudentNumber, inputBuffer, 10);
    inputBuffer[0] = '\0';
    checkOpenRecord();
  }
}

// Handles Chromebook number entry for both sign-out and sign-in.
// # submits the entered digits. * cancels and returns to idle.
// Pressing # with an empty buffer shows an error instead of silently ignoring it.
void handleCNInput(char key) {
  if (!key) return;

  if (key == '*') {
    enterState(S_IDLE);
    return;
  }

  if (key == '#') {
    if (strlen(inputBuffer) > 0) {
      // Copy the typed number and proceed to confirmation logic
      strncpy(currentCN, inputBuffer, 3);
      inputBuffer[0] = '\0';
      if (currentState == S_ENTERING_CN_OUT) {
        confirmSignOut();
      } else {
        confirmSignIn();
      }
    } else {
      // # pressed with nothing typed; prompt the user to enter a number first
      showError("Enter CB #");
    }
    return;
  }

  // Accumulate up to CN_LENGTH digits (max 2 for CBs 1-30)
  int len = strlen(inputBuffer);
  if (len < CN_LENGTH) {
    inputBuffer[len]     = key;
    inputBuffer[len + 1] = '\0';
    updateLCDInput();
  }
}

// Polls the fingerprint sensor once per loop tick while in S_WAITING_FOR_FINGERPRINT.
// On a confident match, looks up the fingerID in adminTable to resolve the admin
// number, then jumps directly to S_ADMIN_MENU. No manual number entry required.
// Times out after FINGERPRINT_TIMEOUT_MS if no finger is detected.
void handleFingerprintInput() {
  if (millis() - stateEnteredAt >= FINGERPRINT_TIMEOUT_MS) {
    showError("Scan timeout");
    return;
  }

  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) return;  // no finger present yet; keep polling
  if (p != FINGERPRINT_OK) {
    showError("Sensor error");
    return;
  }

  // Convert image to feature template
  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) {
    showError("Image error");
    return;
  }

  // Search stored templates for a match
  p = finger.fingerSearch();
  if (p == FINGERPRINT_OK && finger.confidence >= 30) {
    long adminNum = lookupAdminNumber(finger.fingerID);
    if (adminNum == 0) {
      // Fingerprint matched a sensor slot but is not in the admin table.
      // This means the slot was enrolled but not registered here -- deny access.
      Serial.print(F("Fingerprint ID "));
      Serial.print(finger.fingerID);
      Serial.println(F(" not in admin table."));
      showError("Not registered");
      return;
    }
    // Store the resolved admin number directly as a long.
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
// Chromebook Barcode Lookup Table
// =============================================================================

// Maps each Chromebook's physical asset-tag barcode to its CB number (1-30).
// Barcodes are the full strings the scanner produces (e.g. "1H85392GMX").
// Add one row per Chromebook. CB numbers must match the slot numbers students
// enter on the keypad.
//
// HOW TO ADD A CHROMEBOOK:
//   1. Scan the barcode with a terminal open and note the string it produces.
//   2. Add a row below with that string and the CB number assigned to that device.
//   3. Re-upload this sketch.
struct ChromebookEntry {
  const char* barcode;  // full barcode string as scanned
  int         cbNumber; // CB number assigned to this device (1-30)
};

const ChromebookEntry chromebookTable[] = {
  // --- Replace / extend with your real barcodes and CB numbers ---
  { "1H85392GMX", 1 },  // CB 1
  // { "BARCODE2",  2 },
  // { "BARCODE3",  3 },
  // ... add remaining CBs here
};
const int CHROMEBOOK_TABLE_SIZE = sizeof(chromebookTable) / sizeof(chromebookTable[0]);

// Returns the CB number for the given barcode string, or -1 if not found.
int lookupCBNumber(const char* barcode) {
  for (int i = 0; i < CHROMEBOOK_TABLE_SIZE; i++) {
    if (strcmp(chromebookTable[i].barcode, barcode) == 0) {
      return chromebookTable[i].cbNumber;
    }
  }
  return -1;
}

// =============================================================================
// Barcode Validation
// =============================================================================

// Called from loop() once barcodeReady is set by BarcodeParser.
// Looks up the scanned barcode in chromebookTable to resolve it to a CB number,
// then checks that it matches the CB number the student entered (currentCN).
// Unknown barcodes and mismatches both trigger S_BARCODE_ALARM.
void validateBarcode() {
  Serial.print(F("Barcode scanned: "));
  Serial.println(barcodeBuffer);

  int scannedCN = lookupCBNumber(barcodeBuffer);

  if (scannedCN == -1) {
    Serial.println(F("Barcode not recognized."));
    enterState(S_BARCODE_ALARM);
    return;
  }

  if (scannedCN == atoi(currentCN)) {
    Serial.println(F("Barcode match: correct CB confirmed."));
    enterState(S_SIGN_OUT_SUCCESS);
  } else {
    Serial.print(F("Barcode mismatch. Expected CB "));
    Serial.print(currentCN);
    Serial.print(F(", scanned CB "));
    Serial.println(scannedCN);
    enterState(S_BARCODE_ALARM);
  }
}

// =============================================================================
// Business Logic
// =============================================================================

// Checks whether the entered student number has an existing checkout record.
// If no record exists, the student is signing out -> go to S_ENTERING_CN_OUT.
// If a record exists, the student is returning a CB -> go to S_ENTERING_CN_IN.
// The student must type the CB number themselves in both branches; there is no
// auto-fill of currentCN here because handleCNInput() always overwrites it from
// inputBuffer before calling confirmSignIn().
void checkOpenRecord() {
  // Bulk-mode carts do not support individual student sign-out/sign-in.
  if (cartMode == 1) {
    showError("Bulk cart only");
    return;
  }

  long studentNum = strtol(currentStudentNumber, NULL, 10);

  int openCN = -1;
  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == studentNum) {
      openCN = i + 1;  // convert 0-based index to 1-based CB number
      break;
    }
  }

  if (openCN == -1) {
    // No open record: this student does not currently have a CB checked out
    enterState(S_ENTERING_CN_OUT);
  } else {
    // Open record found: student is returning a CB
    enterState(S_ENTERING_CN_IN);
  }
}

// Validates and commits a sign-out: assigns studentNum to the chosen CB slot.
// On success, transitions to S_SCAN_TIMER_ACTIVE to wait for barcode confirmation
// instead of going directly to S_SIGN_OUT_SUCCESS.
// Fails if the CB number is out of range or the slot is already taken.
void confirmSignOut() {
  int cn = atoi(currentCN);
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  if (cn < 1 || cn > MAX_CHROMEBOOKS) {
    showError("Invalid CB #");
    return;
  }

  if (checkoutRecords[cn - 1] != 0) {
    // Another student already has this CB checked out
    showError("CB unavailable");
    return;
  }

  checkoutRecords[cn - 1] = studentNum;
  saveRecord(cn - 1);

  Serial.print(F("Signed out: Student "));
  Serial.print(studentNum);
  Serial.print(F(" -> CB "));
  Serial.print(cn);
  Serial.println(F(" - awaiting barcode scan."));

  // Do NOT go to S_SIGN_OUT_SUCCESS yet; require barcode confirmation first.
  enterState(S_SCAN_TIMER_ACTIVE);
}

// Validates and commits a sign-in: clears the CB slot if it matches studentNum.
// Fails if the CB number is out of range or the record does not match.
void confirmSignIn() {
  int cn = atoi(currentCN);
  long studentNum = strtol(currentStudentNumber, NULL, 10);

  if (cn < 1 || cn > MAX_CHROMEBOOKS) {
    showError("Invalid CB #");
    return;
  }

  if (checkoutRecords[cn - 1] != studentNum) {
    // Either the slot is empty or it belongs to a different student
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

// Assigns the admin's number to every currently available (0) CB slot.
// Only free slots are touched; CBs already checked out by students are skipped.
// Blocked on individual-mode carts.
void processBulkSignOut() {
  if (cartMode == 0) {
    showError("Individ. cart");
    return;
  }

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

// Clears every CB slot that is currently assigned to the admin's number.
// Shows an error if none are found (prevents a silent 0-count success).
// Blocked on individual-mode carts.
void processBulkSignIn() {
  if (cartMode == 0) {
    showError("Individ. cart");
    return;
  }

  long adminNum = currentAdminNum;
  int count = 0;

  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == adminNum) {
      checkoutRecords[i] = 0;
      saveRecord(i);
      count++;
    }
  }

  if (count == 0) {
    // No CBs are currently assigned to this admin number
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

// Copies msg into errorMessage and transitions to the error display state.
// errorMessage is capped at 16 chars to fit LCD line 2.
void showError(const char* msg) {
  strncpy(errorMessage, msg, 16);
  errorMessage[16] = '\0';
  enterState(S_ERROR_DISPLAY);
}

// =============================================================================
// State Transition
// =============================================================================

// Central state transition function. Always call this instead of assigning
// currentState directly so that the timestamp, inputBuffer, serial flush,
// barcode buffer reset, and LCD update all happen consistently on every transition.
void enterState(State newState) {
  currentState   = newState;
  stateEnteredAt = millis();
  inputBuffer[0] = '\0';

  // Flush any stale bytes that accumulated in the SoftwareSerial RX buffer
  // while the sensor was idle. Without this, fingerSearch() may misread a
  // leftover frame from a prior scan and immediately deny access.
  if (newState == S_WAITING_FOR_FINGERPRINT) {
    while (fingerprintSerial.available()) fingerprintSerial.read();
  }

  // Reset the barcode accumulator whenever entering the scan window so a stale
  // result from a previous sign-out cannot carry over into a new one.
  if (newState == S_SCAN_TIMER_ACTIVE) {
    barcodeBuffer[0] = '\0';
    barcodeReady     = false;
  }

  updateLCD();
}

// =============================================================================
// Display
// =============================================================================

// Redraws the entire LCD for the current state.
// Called once per state transition by enterState().
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

    case S_ENTERING_CN_OUT:
      lcd.setRGB(255, 165, 0);  // orange
      lcd.setCursor(0, 0);
      lcd.print(F("Sign OUT"));
      lcd.setCursor(0, 1);
      lcd.print(F("Enter CB #:"));
      break;

    case S_ENTERING_CN_IN:
      lcd.setRGB(0, 100, 255);  // blue
      lcd.setCursor(0, 0);
      lcd.print(F("Sign IN"));
      lcd.setCursor(0, 1);
      lcd.print(F("Enter CB #:"));
      break;

    case S_SCAN_TIMER_ACTIVE:
      lcd.setRGB(255, 165, 0);  // orange: action required
      lcd.setCursor(0, 0);
      lcd.print(F("Scan CB barcode"));
      lcd.setCursor(0, 1);
      lcd.print(F("CB #"));
      lcd.print(currentCN);
      break;

    case S_BARCODE_ALARM:
      lcd.setRGB(255, 0, 0);  // red
      lcd.setCursor(0, 0);
      lcd.print(F("ALARM: Bad scan"));
      lcd.setCursor(0, 1);
      lcd.print(F("*:Admin dismiss"));
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
      lcd.setRGB(255, 0, 0);  // red
      lcd.setCursor(0, 0);
      lcd.print(F("Error:"));
      lcd.setCursor(0, 1);
      lcd.print(errorMessage);
      break;

    case S_WAITING_FOR_FINGERPRINT:
      lcd.setRGB(128, 0, 128);  // purple
      lcd.setCursor(0, 0);
      lcd.print(F("Admin: scan"));
      lcd.setCursor(0, 1);
      lcd.print(F("fingerprint..."));
      break;

    case S_ADMIN_MENU:
      lcd.setRGB(128, 0, 128);
      lcd.setCursor(0, 0);
      // Line 0 shows current mode so admin always knows what the cart is set to.
      // "ADMIN [INDIVID]" = 15 chars, "ADMIN [BULK]   " = 15 chars -- both fit.
      if (cartMode == 1) {
        lcd.print(F("ADMIN [BULK]   "));
      } else {
        lcd.print(F("ADMIN [INDIVID]"));
      }
      lcd.setCursor(0, 1);
      // 1:Md toggles mode, 2:In bulk sign-in, 3:Out bulk sign-out, * cancels
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

// Refreshes only the input line (line 2) while a digit is being typed.
// Clears the line first to erase any previous content, then reprints inputBuffer.
// Called after each keypress in input states to avoid full lcd.clear() flicker.
void updateLCDInput() {
  lcd.setCursor(0, 1);
  lcd.print(F("                "));  // 16 spaces to blank the line
  lcd.setCursor(0, 1);
  lcd.print(inputBuffer);
}
