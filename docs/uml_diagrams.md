# UML State Diagrams

State machine diagrams for the Chromebook Cart Security System, organized by scope.  
Created with assistance from [mermaid.ai](https://mermaid.ai).

## Primary Scope

[View on Mermaid](https://mermaid.ai/d/06c06904-7adf-4590-b95f-602c0413bfc8)

Key states: `WaitingForRFID` -> `ValidatingRFID` -> `Idle` -> `EnteringStudentNumber` -> `ValidatingStudent` -> `CheckOpenRecord` -> `SignOut` / `SignIn` -> `EnteringCNOut` / `EnteringCNIn` -> `ConfirmSignOut` / `ConfirmSignIn` -> `SignOutSuccess` / `SignInSuccess`

## Secondary Scope

[View on Mermaid](https://mermaid.ai/d/2d24661e-4f2a-4950-9454-f2c0c0dd80dd)

Covers barcode verification flow (`BarcodeStandby` -> `ScanTimerActive` -> `ScanValidating` -> `BarcodeAlarmActive`) and admin fingerprint access flow (`WaitingForFingerprint` -> `FingerprintValidating` -> `AdminMenu`).

## Tertiary Scope

[View on Mermaid](https://mermaid.ai/d/7c4aa2ee-2a1c-42bc-b805-3cc3a1620824)

Covers three parallel monitors:
- `DistanceSensorMonitor`: `CartClosed` <-> `CartOpen` -> `CartOpenTooLong`
- `AICameraMonitor`: `Watching` -> `SuspicionElevated` -> `AIAlarmActive`
- `RoomCameraMonitor`: `CameraStreaming` <-> `StreamLostAlarm`
