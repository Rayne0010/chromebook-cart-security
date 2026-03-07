/*
 * Chromebook Cart Security System
 * Cart Arduino
 *
 * Responsibilities:
 *   - 12-digit keypad input for student number + Chromebook number
 *   - Sign-out: associate student number with Chromebook number
 *   - Sign-in: clear association for returned Chromebook
 *   - LCD display for user prompts and feedback
 *
 * States (Primary Scope):
 *   IDLE -> ENTERING_STUDENT_NUMBER -> VALIDATING_STUDENT
 *   -> CHECK_OPEN_RECORD -> SIGN_OUT or SIGN_IN
 *   -> ENTERING_CN -> CONFIRM -> SUCCESS / ERROR
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

#include <Keypad.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

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
LiquidCrystal_I2C lcd(0x27, 16, 2);

// --- State Machine ---
enum State {
  IDLE,
  ENTERING_STUDENT_NUMBER,
  VALIDATING_STUDENT,
  CHECK_OPEN_RECORD,
  SIGN_OUT,
  ENTERING_CN_OUT,
  CONFIRM_SIGN_OUT,
  SIGN_IN,
  ENTERING_CN_IN,
  CONFIRM_SIGN_IN,
  SIGN_OUT_SUCCESS,
  SIGN_IN_SUCCESS,
  ERROR_DISPLAY
};

State currentState = IDLE;

// --- Data ---
// Simple in-memory records: index = Chromebook number, value = student number (0 = available)
const int MAX_CHROMEBOOKS = 30;
int checkoutRecords[MAX_CHROMEBOOKS];  // 0 means not checked out

const int STUDENT_NUMBER_LENGTH = 9;
const int CN_LENGTH = 2;

String inputBuffer = "";
String currentStudentNumber = "";
String currentCN = "";
String errorMessage = "";

unsigned long stateEnteredAt = 0;
const int ERROR_DISPLAY_DURATION_MS = 3000;

void setup() {
  Serial.begin(9600);
  lcd.init();
  lcd.backlight();

  // Initialize all Chromebooks as available
  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    checkoutRecords[i] = 0;
  }

  enterState(IDLE);
  Serial.println("Cart system ready.");
}

void loop() {
  char key = keypad.getKey();

  switch (currentState) {
    case IDLE:
      if (key && key != '*' && key != '#') {
        inputBuffer = String(key);
        enterState(ENTERING_STUDENT_NUMBER);
      }
      break;

    case ENTERING_STUDENT_NUMBER:
      handleStudentNumberInput(key);
      break;

    case ENTERING_CN_OUT:
    case ENTERING_CN_IN:
      handleCNInput(key);
      break;

    case ERROR_DISPLAY:
      if (millis() - stateEnteredAt >= ERROR_DISPLAY_DURATION_MS) {
        enterState(IDLE);
      }
      break;

    case SIGN_OUT_SUCCESS:
    case SIGN_IN_SUCCESS:
      if (millis() - stateEnteredAt >= ERROR_DISPLAY_DURATION_MS) {
        enterState(IDLE);
      }
      break;

    default:
      break;
  }
}

void handleStudentNumberInput(char key) {
  if (!key) return;

  if (key == '*') {
    enterState(IDLE);
    return;
  }

  if (key != '#') {
    if (inputBuffer.length() < STUDENT_NUMBER_LENGTH) {
      inputBuffer += key;
      updateLCDInput();
    }
  }

  if (inputBuffer.length() == STUDENT_NUMBER_LENGTH) {
    currentStudentNumber = inputBuffer;
    inputBuffer = "";
    checkOpenRecord();
  }
}

void checkOpenRecord() {
  int studentNum = currentStudentNumber.toInt();

  // Check if student has an open checkout
  int openCN = -1;
  for (int i = 0; i < MAX_CHROMEBOOKS; i++) {
    if (checkoutRecords[i] == studentNum) {
      openCN = i + 1;
      break;
    }
  }

  if (openCN == -1) {
    // No open record — student is signing out
    enterState(SIGN_OUT);
  } else {
    // Open record exists — student is returning
    currentCN = String(openCN);
    enterState(SIGN_IN);
  }
}

void handleCNInput(char key) {
  if (!key) return;

  if (key == '*') {
    enterState(IDLE);
    return;
  }

  if (key == '#') {
    if (inputBuffer.length() > 0) {
      currentCN = inputBuffer;
      inputBuffer = "";
      if (currentState == ENTERING_CN_OUT) {
        confirmSignOut();
      } else {
        confirmSignIn();
      }
    }
    return;
  }

  if (inputBuffer.length() < CN_LENGTH) {
    inputBuffer += key;
    updateLCDInput();
  }
}

void confirmSignOut() {
  int cn = currentCN.toInt();
  int studentNum = currentStudentNumber.toInt();

  if (cn < 1 || cn > MAX_CHROMEBOOKS) {
    showError("Invalid CB #");
    return;
  }

  if (checkoutRecords[cn - 1] != 0) {
    showError("CB unavailable");
    return;
  }

  checkoutRecords[cn - 1] = studentNum;
  Serial.print("Signed out: Student ");
  Serial.print(studentNum);
  Serial.print(" -> CB ");
  Serial.println(cn);

  enterState(SIGN_OUT_SUCCESS);
}

void confirmSignIn() {
  int cn = currentCN.toInt();
  int studentNum = currentStudentNumber.toInt();

  if (cn < 1 || cn > MAX_CHROMEBOOKS) {
    showError("Invalid CB #");
    return;
  }

  if (checkoutRecords[cn - 1] != studentNum) {
    showError("No match found");
    return;
  }

  checkoutRecords[cn - 1] = 0;
  Serial.print("Signed in: CB ");
  Serial.print(cn);
  Serial.print(" from Student ");
  Serial.println(studentNum);

  enterState(SIGN_IN_SUCCESS);
}

void showError(String msg) {
  errorMessage = msg;
  enterState(ERROR_DISPLAY);
}

void enterState(State newState) {
  currentState = newState;
  stateEnteredAt = millis();
  inputBuffer = "";
  updateLCD();
}

void updateLCD() {
  lcd.clear();
  switch (currentState) {
    case IDLE:
      lcd.setCursor(0, 0);
      lcd.print("Enter student #");
      break;
    case ENTERING_STUDENT_NUMBER:
      lcd.setCursor(0, 0);
      lcd.print("Student #:");
      lcd.setCursor(0, 1);
      lcd.print(inputBuffer);
      break;
    case SIGN_OUT:
      lcd.setCursor(0, 0);
      lcd.print("Sign OUT");
      lcd.setCursor(0, 1);
      lcd.print("Enter CB #:");
      enterState(ENTERING_CN_OUT);
      break;
    case SIGN_IN:
      lcd.setCursor(0, 0);
      lcd.print("Sign IN");
      lcd.setCursor(0, 1);
      lcd.print("Enter CB #:");
      enterState(ENTERING_CN_IN);
      break;
    case SIGN_OUT_SUCCESS:
      lcd.setCursor(0, 0);
      lcd.print("Signed OUT!");
      lcd.setCursor(0, 1);
      lcd.print("CB #" + currentCN);
      break;
    case SIGN_IN_SUCCESS:
      lcd.setCursor(0, 0);
      lcd.print("Signed IN!");
      lcd.setCursor(0, 1);
      lcd.print("CB #" + currentCN);
      break;
    case ERROR_DISPLAY:
      lcd.setCursor(0, 0);
      lcd.print("Error:");
      lcd.setCursor(0, 1);
      lcd.print(errorMessage);
      break;
    default:
      break;
  }
}

void updateLCDInput() {
  lcd.setCursor(0, 1);
  lcd.print("                ");
  lcd.setCursor(0, 1);
  lcd.print(inputBuffer);
}
