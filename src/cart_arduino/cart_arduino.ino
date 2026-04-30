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
 *   S_IDLE -(*)--> S_WAITING_FOR_FINGERPRINT
 *   -> S_ADMIN_MENU
 *   -> S_BULK_CONFIRM -> S_BULK_COMPLETE
 *   -> S_BULK_IN_CONFIRM -> S_BULK_IN_COMPLETE
 *
 * States (Secondary Scope - Barcode):
 *   S_SIGN_OUT_SUCCESS -(3s)--> S_SCAN_TIMER_ACTIVE
 *   -- correct CB scanned --> S_IDLE
 *   -- wrong/unknown/timeout --> S_BARCODE_ALARM -(*)--> S_WAITING_FOR_FINGERPRINT
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
 *     S_ENTERING_CN_IN, and S_ENTERING_ADMIN_NUMBER auto-reset to S_IDLE
 *     after INPUT_TIMEOUT_MS of inactivity.
 *   - Bulk op count now displayed on LCD line 2 of S_BULK_COMPLETE and
 *     S_BULK_IN_COMPLETE so the admin can confirm how many CBs were processed.
 *   - Dead itoa() pre-fill of currentCN removed from checkOpenRecord().
 *     handleCNInput() always overwrites currentCN from inputBuffer before
 *     calling confirmSignIn(), so the pre-fill had no effect.
 *   - handleCNInput() now shows an "Enter CB #" error if # is pressed while
 *     the input buffer is empty, instead of silently ignoring the keypress.
 *   - Cart mode added: each cart is either INDIVIDUAL (students sign out CBs
 *     one at a time; bulk ops blocked) or BULK (only admin bulk sign-out/in;
 *     student individual sign-out blocked with "Bulk cart only" error).
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
 *   - S_BULK_COMPLETE LCD line 2 changed from "X CBs signed out" (17 chars
 *     with a 2-digit count, clipped the trailing 't' on a 16-char display)
 *     to "X CBs out" (10 chars max).
 *   - processBulkSignOut() now shows a "No free CBs" error if every slot is
 *     already taken, mirroring processBulkSignIn()'s zero-count guard
 *     instead of silently displaying "0 CBs out".
 *   - Admin menu timeout timer now resets when the admin presses 1 to toggle
 *     cart mode. Without this, the existing stateEnteredAt was untouched on
 *     toggle, so an admin lingering near the timeout could be kicked to
 *     idle immediately after toggling.
 *   - S_IDLE digit input is now ignored on bulk-mode carts. Previously a
 *     student could type all 9 digits before checkOpenRecord() told them
 *     the cart was bulk-only; the keypad now gates input at idle so only
 *     * (admin fingerprint) is accepted in bulk mode.
 *   - Bulk-mode S_IDLE line 2 changed from the awkward truncation
 *     "Admin accs only" to "Admin only".
 *   - WAVE-14810 Waveshare 1D/2D barcode scanner integrated on
 *     SoftwareSerial pins 9 (RX) / 10 (TX) at 9600 baud. Two new states
 *     added: S_SCAN_TIMER_ACTIVE follows S_SIGN_OUT_SUCCESS and gives the
 *     student SCAN_TIMER_MS (30s) to scan the CB they just signed out.
 *     S_BARCODE_ALARM is entered on wrong/unknown barcode or scan timeout
 *     and is cleared by admin fingerprint via the existing flow.
 *     A 30-slot cbTable[] in PROGMEM maps barcode strings to CB numbers;
 *     placeholders to be replaced with real asset-tag barcodes during
 *     deployment. SoftwareSerial .listen() is now called explicitly in
 *     enterState() to switch the active receiver between fingerprintSerial
 *     and barcodeSerial -- only one SoftwareSerial can RX at a time on AVR.
 *     Sign-IN does not require barcode verification (per UML); only sign-OUT
 *     triggers the scan timer. Bulk operations bypass barcode verification
 *     entirely. expectedCN is set in confirmSignOut() so the scan timer
 *     state knows which CB to validate against.
 *     One-time hardware setup required before deployment: scan the "switch
 *     to UART output mode" config code from the WAVE-14810 user manual to
 *     change the scanner from its default HID-keyboard mode to UART output.
 *   - Sticky alarm flag (alarmActive) added to prevent the barcode alarm
 *     from being cleared by a non-admin triggering a fingerprint timeout.
 *     Without this, a student could press * at the alarm screen, wait for
 *     fingerprint timeout, and let S_ERROR_DISPLAY -> S_IDLE silently clear
 *     the alarm. enterState() now intercepts S_IDLE transitions while
 *     alarmActive is true and redirects back to S_BARCODE_ALARM. The flag
 *     is set on entry to S_BARCODE_ALARM and only cleared after a
 *     successful admin fingerprint match in handleFingerprintInput().
 *   - alarmActive is now persisted to EEPROM at byte 125 so the alarm
 *     survives power loss. Without this, an attacker could trip the alarm,
 *     unplug the cart, plug it back in, and land on a clean idle screen.
 *     The EEPROM write is gated on the actual flag transition (false -> true
 *     and true -> false) rather than firing on every entry to S_BARCODE_ALARM,
 *     since the sticky redirect re-enters that state on every loop iteration
 *     while the alarm is active and an unconditional write would exhaust the
 *     EEPROM byte's ~100k write endurance.
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

#include <Keypad.h>
#include <Wire.h>
#include <rgb_lcd.h>
#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>
#include <EEPROM.h>

// =============================================================================
// Hardware Setup
// =============================================================================

// -- Keypad --
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

// -- LCD --
// Grove LCD RGB Backlight on I2C (A4/A5). No address needed; handled by library.
rgb_lcd lcd;

// -- Fingerprint Sensor --
// Adafruit fingerprint sensor on SoftwareSerial: RX = pin A0, TX = pin A1.
// Templates are stored on the sensor's onboard flash, not in Arduino RAM.
SoftwareSerial fingerprintSerial(A0, A1);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&fingerprintSerial);

// -- Barcode Scanner --
// Waveshare WAVE-14810 1D/2D barcode scanner on SoftwareSerial: RX = pin 9
// (connect to scanner's TX), TX = pin 10 (connect to scanner's RX).
// UART defaults: 9600 baud, 8N1, terminator = CR.
//
// IMPORTANT one-time setup before deployment: the scanner ships configured
// for HID-keyboard output. It must be switched to UART output mode by
// scanning the "Setting code to enable UART" barcode from the user manual
// (Waveshare wiki: waveshare.com/wiki/Barcode_Scanner_Module). The setting
// is saved to the scanner's onboard EEPROM and persists across power cycles.
//
// SoftwareSerial constraint: only one instance can receive at a time on AVR.
// enterState() calls .listen() on whichever instance the new state needs,
// so the fingerprint sensor and barcode scanner never compete for RX.
//
// Power: scanner draws ~135 mA when actively scanning. Within the Uno's
// 5V regulator budget when running on a 9V external supply, but consider a
// dedicated 5V supply for production builds with multiple peripherals.
SoftwareSerial barcodeSerial(9, 10);

// Trigger command from the WAVE-14810 manual: tells the scanner to start a
// single scan attempt with its internal timeout. Sent on entry to
// S_SCAN_TIMER_ACTIVE and re-sent every SCAN_RETRIGGER_MS so the scanner
// stays armed even if a barcode briefly leaves the field of view.
const uint8_t SCAN_TRIGGER_CMD[] = { 0x16, 0x54, 0x0D };
const unsigned long SCAN_RETRIGGER_MS = 3000;

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
  S_SIGN_OUT_SUCCESS,        // confirmation message shown for 3s then -> SCAN_TIMER
  S_SIGN_IN_SUCCESS,         // confirmation message shown for 3s then -> IDLE
  S_ERROR_DISPLAY,           // error message shown for 3s then -> IDLE
  S_WAITING_FOR_FINGERPRINT, // admin flow: waiting for finger on sensor
  S_ADMIN_MENU,              // admin flow: choose bulk-out (3), bulk-in (2), or back (*)
  S_BULK_CONFIRM,            // admin flow: confirm sign-out of entire cart
  S_BULK_COMPLETE,           // admin flow: bulk sign-out done, shown for 3s
  S_BULK_IN_CONFIRM,         // admin flow: confirm sign-in of entire cart
  S_BULK_IN_COMPLETE,        // admin flow: bulk sign-in done, shown for 3s
  S_SCAN_TIMER_ACTIVE,       // post-sign-out: waiting for student to scan their CB
  S_BARCODE_ALARM            // wrong/unknown/missed scan; awaiting admin reset
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
//   Byte    125:   alarmActive (0 = clear, 1 = active)
const int EEPROM_BASE_ADDR      = 0;
const int EEPROM_MAGIC_ADDR     = MAX_CHROMEBOOKS * sizeof(long);  // = 120
const long EEPROM_MAGIC         = 12345678L;
const int EEPROM_CART_MODE_ADDR = EEPROM_MAGIC_ADDR + sizeof(long);  // = 124
const int EEPROM_ALARM_ADDR     = EEPROM_CART_MODE_ADDR + 1;         // = 125

// Cart operating mode, persisted to EEPROM.
// 0 = INDIVIDUAL: students sign CBs in/out one at a time; bulk ops blocked.
// 1 = BULK: only admin bulk sign-out/in allowed; student individual flow blocked.
byte cartMode = 0;

// Input length constraints
const int STUDENT_NUMBER_LENGTH = 9;  // exactly 9 digits
const int CN_LENGTH             = 2;  // Chromebook numbers 1-30 (1 or 2 digits)

// Timeout durations (milliseconds)
const unsigned long FINGERPRINT_TIMEOUT_MS      = 10000;  // 10s to scan finger
const unsigned long INPUT_TIMEOUT_MS            = 30000;  // 30s idle on any input state
const unsigned long ADMIN_MENU_TIMEOUT_MS       = 20000;  // 20s idle on admin menu
const unsigned long MESSAGE_DISPLAY_DURATION_MS = 3000;   // 3s for success/error messages
const unsigned long SCAN_TIMER_MS               = 30000;  // 30s window to scan after sign-out

// Fixed-size char arrays replace String objects to avoid heap fragmentation.
// Sizes include the null terminator.
char inputBuffer[10]          = "";  // active typing buffer (max 9 digits + \0)
char currentStudentNumber[10] = "";  // student number confirmed this session
char currentAdminNumber[10]   = "";  // admin number confirmed after fingerprint
char currentCN[3]             = "";  // Chromebook number confirmed this session (max 2 digits + \0)
char errorMessage[17]         = "";  // error text for LCD line 2 (max 16 chars + \0)

// Barcode scanner receive buffer. Bytes accumulate here as the scanner streams
// the barcode over UART; the buffer is flushed on each terminator (CR/LF) and
// at every transition into S_SCAN_TIMER_ACTIVE.
const byte BARCODE_BUFFER_SIZE = 24;
char barcodeBuffer[BARCODE_BUFFER_SIZE] = "";
byte barcodePos = 0;

// CB number the student just signed out. Set in confirmSignOut(); checked
// against the looked-up CB number of the scanned barcode in S_SCAN_TIMER_ACTIVE.
int expectedCN = 0;

// Last time SCAN_TRIGGER_CMD was sent to the scanner; used to retrigger
// every SCAN_RETRIGGER_MS during S_SCAN_TIMER_ACTIVE.
unsigned long lastTriggerAt = 0;

// Sticky alarm flag. Set true when entering S_BARCODE_ALARM, cleared only
// when an admin successfully authenticates via fingerprint. While true,
// every transition into S_IDLE is intercepted in enterState() and redirected
// back to S_BARCODE_ALARM, so a non-admin cannot clear the alarm by simply
// triggering a fingerprint timeout (which would otherwise route through
// S_ERROR_DISPLAY -> S_IDLE).
//
// Persisted to EEPROM so the alarm survives power loss. Without this, an
// attacker could trip the alarm, unplug the cart, plug it back in, and land
// on a clean idle screen.
bool alarmActive = false;

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

// Write the current alarmActive flag to EEPROM.
// Called whenever the alarm state changes (set on alarm trigger, cleared on
// successful admin auth) so the alarm survives a power cycle.
void saveAlarmState() {
  byte v = alarmActive ? 1 : 0;
  EEPROM.put(EEPROM_ALARM_ADDR, v);
}

// Load all checkout records, cartMode, and alarmActive from EEPROM on boot.
// If the magic number is missing (first power-on or after a flash), all records
// are initialized to 0, cartMode is set to INDIVIDUAL (0), alarmActive is set
// to 0, and the magic number is written so subsequent boots load real data.
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
    alarmActive = false;
    byte alarmByte = 0;
    EEPROM.put(EEPROM_ALARM_ADDR, alarmByte);
    EEPROM.put(EEPROM_MAGIC_ADDR, EEPROM_MAGIC);
    Serial.println(F("EEPROM initialized."));
  } else {
    // Normal boot: load previously saved records, mode, and alarm state into RAM.
    for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
      EEPROM.get(EEPROM_BASE_ADDR + i * sizeof(long), checkoutRecords[i]);
    }
    EEPROM.get(EEPROM_CART_MODE_ADDR, cartMode);
    // Guard against corrupted mode byte (anything other than 0 or 1)
    if (cartMode != 0 && cartMode != 1) cartMode = 0;
    byte alarmByte;
    EEPROM.get(EEPROM_ALARM_ADDR, alarmByte);
    // Guard against corrupted alarm byte (anything other than 0 or 1)
    if (alarmByte != 0 && alarmByte != 1) alarmByte = 0;
    alarmActive = (alarmByte == 1);
    if (alarmActive) {
      Serial.println(F("Records loaded from EEPROM. Alarm was active."));
    } else {
      Serial.println(F("Records loaded from EEPROM."));
    }
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
  // -- Example admin entries (replace with real data before deployment) --
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
// Chromebook Barcode Lookup Table
// =============================================================================

// Maps each Chromebook's asset-tag barcode (as read by the WAVE-14810 scanner)
// to its slot number in the cart (1 - MAX_CHROMEBOOKS). Stored in PROGMEM
// because 30 entries x 17 bytes = 510 bytes, which would consume 25% of the
// Uno's 2 KB SRAM if kept in RAM.
//
// HOW TO POPULATE:
//   1. Connect the scanner to a computer in keyboard mode (default factory
//      setting) and scan each Chromebook's asset-tag barcode into a text
//      editor to capture the exact string.
//   2. Replace the corresponding placeholder below with the captured string.
//   3. Re-upload this sketch. The cart will recognize that barcode as the
//      mapped CB number from then on.
//
// The barcode field is 16 chars max (15 + null terminator). If a Chromebook's
// barcode is longer than 15 chars, increase the array size in CBEntry, the
// BARCODE_BUFFER_SIZE constant, and the placeholder lengths together.
struct CBEntry {
  char    barcode[16];  // up to 15 chars + \0
  uint8_t cbNumber;     // 1 - MAX_CHROMEBOOKS
};

const CBEntry cbTable[] PROGMEM = {
  // -- Replace placeholders with real asset-tag barcodes as they're captured --
  { "CB001-PLACEHLD",  1 },
  { "CB002-PLACEHLD",  2 },
  { "CB003-PLACEHLD",  3 },
  { "CB004-PLACEHLD",  4 },
  { "CB005-PLACEHLD",  5 },
  { "CB006-PLACEHLD",  6 },
  { "CB007-PLACEHLD",  7 },
  { "CB008-PLACEHLD",  8 },
  { "CB009-PLACEHLD",  9 },
  { "CB010-PLACEHLD", 10 },
  { "CB011-PLACEHLD", 11 },
  { "CB012-PLACEHLD", 12 },
  { "CB013-PLACEHLD", 13 },
  { "CB014-PLACEHLD", 14 },
  { "CB015-PLACEHLD", 15 },
  { "CB016-PLACEHLD", 16 },
  { "CB017-PLACEHLD", 17 },
  { "CB018-PLACEHLD", 18 },
  { "CB019-PLACEHLD", 19 },
  { "CB020-PLACEHLD", 20 },
  { "CB021-PLACEHLD", 21 },
  { "CB022-PLACEHLD", 22 },
  { "CB023-PLACEHLD", 23 },
  { "CB024-PLACEHLD", 24 },
  { "CB025-PLACEHLD", 25 },
  { "CB026-PLACEHLD", 26 },
  { "CB027-PLACEHLD", 27 },
  { "CB028-PLACEHLD", 28 },
  { "CB029-PLACEHLD", 29 },
  { "CB030-PLACEHLD", 30 },
};
const int CB_TABLE_SIZE = sizeof(cbTable) / sizeof(cbTable[0]);

// Returns the CB number for the given barcode, or 0 if not in the table.
// Reads each entry out of PROGMEM into a small stack-allocated CBEntry to
// perform the comparison; this keeps RAM usage to one CBEntry's worth (~17 B)
// regardless of CB_TABLE_SIZE.
int lookupCBNumber(const char* barcode) {
  CBEntry entry;
  for (int i = 0; i < CB_TABLE_SIZE; i++) {
    memcpy_P(&entry, &cbTable[i], sizeof(CBEntry));
    if (strcmp(barcode, entry.barcode) == 0) {
      return entry.cbNumber;
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

  // Barcode scanner: 9600 baud per WAVE-14810 default UART setting.
  // begin() leaves this instance in the listening state; enterState() will
  // switch to fingerprintSerial.listen() when the admin flow needs it, then
  // switch back here on entry to S_SCAN_TIMER_ACTIVE.
  barcodeSerial.begin(9600);

  enterState(S_IDLE);
  Serial.println(F("Cart system ready."));
}

// =============================================================================
// Main Loop
// =============================================================================

void loop() {
  // Poll the keypad once per loop iteration. Returns '\0' if no key is pressed.
  char key = keypad.getKey();

  switch (currentState) {

    case S_IDLE:
      // Any digit starts student number entry. * triggers admin fingerprint flow.
      // # is ignored in idle (no context to submit).
      // On bulk-mode carts, digit presses are ignored entirely so students
      // don't waste time typing all 9 digits before being told the cart is
      // bulk-only. Only * (admin access) is accepted.
      if (key && key != '*' && key != '#') {
        if (cartMode == 1) break;  // bulk cart -- ignore student input at the keypad
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

    // S_ERROR_DISPLAY and S_SIGN_IN_SUCCESS just display a message and return
    // to idle. S_SIGN_OUT_SUCCESS is special: it transitions into the barcode
    // scan timer so the student must verify the CB they just signed out.
    case S_ERROR_DISPLAY:
    case S_SIGN_IN_SUCCESS:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) {
        enterState(S_IDLE);
      }
      break;

    case S_SIGN_OUT_SUCCESS:
      if (millis() - stateEnteredAt >= MESSAGE_DISPLAY_DURATION_MS) {
        // After the success confirmation, require the student to scan the
        // physical barcode on the CB they just signed out. expectedCN was
        // set in confirmSignOut() so S_SCAN_TIMER_ACTIVE knows what to match.
        enterState(S_SCAN_TIMER_ACTIVE);
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
      // Auto-cancel if no key pressed within the timeout window.
      if (millis() - stateEnteredAt >= ADMIN_MENU_TIMEOUT_MS) {
        enterState(S_IDLE);
        break;
      }
      // 1 = toggle cart mode, 2 = bulk sign-in, 3 = bulk sign-out, * = back to idle
      if (key == '1') {
        // Block mode toggle if any CBs are still checked out to prevent
        // orphaned records that can never be cleared in the new mode.
        int outstanding = 0;
        for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
          if (checkoutRecords[i] != 0) outstanding++;
        }
        if (outstanding > 0) {
          showError("CBs still out");
          break;
        }
        cartMode = 1 - cartMode;  // toggle between 0 and 1
        saveCartMode();
        Serial.print(F("Cart mode set to: "));
        Serial.println(cartMode == 1 ? F("BULK") : F("INDIVIDUAL"));
        // Reset the admin menu timeout: pressing 1 is active engagement,
        // so the admin shouldn't be kicked to idle immediately after toggling.
        stateEnteredAt = millis();
        updateLCD();  // re-render menu to show new mode
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

    case S_SCAN_TIMER_ACTIVE:
      // Re-arm the scanner periodically so it stays ready to read even if
      // the student's first attempt missed (CB was outside the field of view,
      // angle was bad, etc.). Sending a trigger while the scanner is already
      // mid-scan is harmless; it just resets the scanner's internal timeout.
      if (millis() - lastTriggerAt >= SCAN_RETRIGGER_MS) {
        barcodeSerial.write(SCAN_TRIGGER_CMD, sizeof(SCAN_TRIGGER_CMD));
        lastTriggerAt = millis();
      }
      pollBarcodeScanner();

      // Overall window expired without a valid scan -> trigger the alarm.
      if (millis() - stateEnteredAt >= SCAN_TIMER_MS) {
        Serial.println(F("Scan timeout - alarm"));
        enterState(S_BARCODE_ALARM);
      }
      break;

    case S_BARCODE_ALARM:
      // Admin can clear the alarm via fingerprint. * starts the existing
      // fingerprint flow which on success lands in S_ADMIN_MENU; the admin
      // can then exit normally with * to return to S_IDLE. No keypad input
      // from students will dismiss the alarm.
      if (key == '*') {
        enterState(S_WAITING_FOR_FINGERPRINT);
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
    // Populate currentAdminNumber from the lookup result so bulk functions
    // can use it via strtol() without any other changes.
    ltoa(adminNum, currentAdminNumber, 10);
    Serial.print(F("Admin matched. FP ID: "));
    Serial.print(finger.fingerID);
    Serial.print(F(" -> Admin: "));
    Serial.println(currentAdminNumber);
    // Successful admin authentication clears any active barcode alarm so
    // S_IDLE is no longer redirected back to S_BARCODE_ALARM. If the admin
    // entered the fingerprint flow for a different reason (e.g. bulk ops),
    // clearing a non-set flag is a no-op and we skip the EEPROM write.
    if (alarmActive) {
      alarmActive = false;
      saveAlarmState();
    }
    enterState(S_ADMIN_MENU);
  } else {
    showError("Access denied");
  }
}

// Drains the SoftwareSerial RX buffer for the WAVE-14810 scanner. Bytes are
// accumulated into barcodeBuffer until a CR or LF terminator is seen, at
// which point processBarcode() is called with the complete null-terminated
// barcode string. Non-printable bytes are filtered out so the occasional
// stray byte (e.g. from a trigger-command echo) doesn't corrupt the buffer.
void pollBarcodeScanner() {
  while (barcodeSerial.available()) {
    char c = barcodeSerial.read();

    if (c == '\r' || c == '\n') {
      // End-of-barcode terminator. processBarcode() will reset us to a new
      // state, so the buffer reset here only matters if barcodePos was 0
      // (an empty terminator caused by CRLF or stray newline -- ignore it).
      if (barcodePos > 0) {
        barcodeBuffer[barcodePos] = '\0';
        processBarcode();
        barcodePos = 0;
      }
    } else if (c >= ' ' && c <= '~') {
      // Printable ASCII: append if there's room. Anything else is dropped.
      if (barcodePos < BARCODE_BUFFER_SIZE - 1) {
        barcodeBuffer[barcodePos++] = c;
      } else {
        // Buffer overflow: barcode is longer than BARCODE_BUFFER_SIZE - 1.
        // Reset and ignore this scan; expanding the buffer will allow
        // longer barcodes through.
        barcodePos = 0;
      }
    }
  }
}

// Looks up the scanned barcode in cbTable and either confirms the sign-out
// (returning to S_IDLE) or trips the alarm (S_BARCODE_ALARM) on a mismatch.
// Called from pollBarcodeScanner() once a complete barcode has been received.
void processBarcode() {
  Serial.print(F("Scanned: "));
  Serial.println(barcodeBuffer);

  int scannedCN = lookupCBNumber(barcodeBuffer);

  if (scannedCN == 0) {
    // Barcode is not in cbTable -- either not a CB at all (random object)
    // or a CB whose barcode hasn't been registered in the lookup table yet.
    Serial.println(F("Unknown barcode - alarm"));
    enterState(S_BARCODE_ALARM);
    return;
  }

  if (scannedCN != expectedCN) {
    // Barcode is a known CB, but not the one this student signed out for.
    // This catches a student grabbing the wrong CB (or grabbing two).
    Serial.print(F("Wrong CB: scanned "));
    Serial.print(scannedCN);
    Serial.print(F(", expected "));
    Serial.print(expectedCN);
    Serial.println(F(" - alarm"));
    enterState(S_BARCODE_ALARM);
    return;
  }

  // Match: scanned CB equals the one signed out. Verification complete.
  Serial.print(F("CB "));
  Serial.print(scannedCN);
  Serial.println(F(" verified."));
  enterState(S_IDLE);
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
  Serial.println(cn);

  // Remember which CB was just signed out so S_SCAN_TIMER_ACTIVE can verify
  // the scanned barcode matches. The success message displays for 3s first,
  // then the loop transitions S_SIGN_OUT_SUCCESS -> S_SCAN_TIMER_ACTIVE.
  expectedCN = cn;

  enterState(S_SIGN_OUT_SUCCESS);
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

  long adminNum = strtol(currentAdminNumber, NULL, 10);
  int count = 0;

  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == 0) {
      checkoutRecords[i] = adminNum;
      saveRecord(i);
      count++;
    }
  }

  if (count == 0) {
    // Every slot was already taken (e.g. another admin already bulk-signed-out).
    // Mirror processBulkSignIn's behaviour rather than showing a misleading "0 CBs".
    showError("No free CBs");
    return;
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
// and LCD update all happen consistently on every transition.
void enterState(State newState) {
  // Sticky alarm interception: while alarmActive is set, any attempt to
  // transition into S_IDLE is redirected back to S_BARCODE_ALARM. This keeps
  // the alarm visible and uncleared until an admin successfully authenticates
  // (which clears alarmActive in handleFingerprintInput).
  if (newState == S_IDLE && alarmActive) {
    newState = S_BARCODE_ALARM;
  }
  // Mark the alarm sticky from the moment it activates, regardless of how
  // we got here (timeout, wrong CB, unknown barcode). Persist to EEPROM only
  // when the flag actually transitions from false to true; the redirect above
  // routes through here on every re-entry to S_BARCODE_ALARM, so an
  // unconditional write would burn EEPROM cycles unnecessarily.
  if (newState == S_BARCODE_ALARM && !alarmActive) {
    alarmActive = true;
    saveAlarmState();
  }

  currentState   = newState;
  stateEnteredAt = millis();
  inputBuffer[0] = '\0';

  // SoftwareSerial constraint: only one instance can receive at a time on
  // AVR. Switch the active listener to whichever sensor the new state needs,
  // and flush its RX buffer so stale bytes from a prior session don't get
  // mistaken for fresh data.
  if (newState == S_WAITING_FOR_FINGERPRINT) {
    fingerprintSerial.listen();
    while (fingerprintSerial.available()) fingerprintSerial.read();
  } else if (newState == S_SCAN_TIMER_ACTIVE) {
    barcodeSerial.listen();
    while (barcodeSerial.available()) barcodeSerial.read();
    barcodePos = 0;
    // Trigger immediately on entry so the scanner is armed before the loop
    // ticks; the periodic retrigger in loop() handles re-arming after that.
    barcodeSerial.write(SCAN_TRIGGER_CMD, sizeof(SCAN_TRIGGER_CMD));
    lastTriggerAt = millis();
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
        // "Admin only" reads cleaner than the previous "Admin accs only"
        // (an awkward truncation of "access"). Bulk-mode users press *
        // for fingerprint access; no other prompt is needed.
        lcd.print(F("Admin only"));
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
      // "X CBs out" stays under 16 chars even with a 2-digit count (max 10
      // chars). The previous "X CBs signed out" was 17 with 2 digits and
      // clipped the trailing 't' on a 16-char display.
      lcd.print(F(" CBs out"));
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

    case S_SCAN_TIMER_ACTIVE:
      lcd.setRGB(255, 165, 0);  // orange (matches sign-out color family)
      lcd.setCursor(0, 0);
      lcd.print(F("Scan CB #"));
      lcd.print(expectedCN);
      lcd.setCursor(0, 1);
      lcd.print(F("Show barcode..."));
      break;

    case S_BARCODE_ALARM:
      lcd.setRGB(255, 0, 0);  // red
      lcd.setCursor(0, 0);
      lcd.print(F("!! ALARM !!"));
      lcd.setCursor(0, 1);
      // Tells the admin how to clear the alarm. * starts the existing
      // fingerprint flow which on success transitions to S_ADMIN_MENU.
      lcd.print(F("*:Admin reset"));
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
