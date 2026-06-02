/*
 * ChromeLock - Design Mode
 *
 * Standalone sketch for physical cart construction.
 * Initializes the LCD and holds a static message.
 * No state machine, no keypad logic.
 *
 * Upload this while building/wiring the cart structure.
 * When done, re-upload cart_arduino.ino.
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

#include <Wire.h>
#include <LiquidCrystal_I2C.h>

LiquidCrystal_I2C lcd(0x27, 16, 2);

void setup() {
  lcd.init();
  lcd.backlight();
  lcd.setCursor(0, 0);
  lcd.print("  DESIGN MODE   ");
  lcd.setCursor(0, 1);
  lcd.print(" System Unlocked");
}

void loop() {
  // Nothing - holds indefinitely
}
