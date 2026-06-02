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
  doorServo.write(UNLOCKED_ANGLE);
}

void loop() {
  // Holds unlocked indefinitely
}
