/*
 * ChromeLock - Servo Unlock Test
 *
 * Moves servo to unlocked position and holds it there.
 * Use this while designing the physical cart structure.
 * Re-upload entrance_arduino.ino when done.
 *
 * Team: Julian D., Ethan A., Lennon F. - TEJ4M
 */

#include <Servo.h>

#define SERVO_PIN      6
#define UNLOCKED_ANGLE 90

Servo doorServo;

void setup() {
  doorServo.attach(SERVO_PIN);
  delay(500);                      // Give servo time to initialize
  doorServo.write(UNLOCKED_ANGLE);
  delay(1000);                     // Hold long enough to reach position
}

void loop() {
  doorServo.write(UNLOCKED_ANGLE); // Keep resending in case of signal drop
  delay(100);
}
