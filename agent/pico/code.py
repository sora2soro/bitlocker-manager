# BitLocker Manager — Pi Pico unlock rig (CircuitPython)
# ------------------------------------------------------
# Turns a ~$4 Raspberry Pi Pico into the "plug-and-play" unlock key for models
# whose recovery screen only accepts a TYPED numeric key.
#
# How it works:
#   * The agent writes the 48-digit recovery key to  blm_secret.txt  on the Pico.
#     (For a first typing TEST, just create blm_secret.txt yourself with some digits.)
#   * On insertion, this reads the file and TYPES the digits, then presses Enter.
#   * The BitLocker recovery field is numeric-only, so only digits are needed.
#
# TESTING TIP: plug the Pico into a PC, open Notepad, click into it, then reset/replug
#   the Pico. It should type the digits from blm_secret.txt into Notepad.
#
# If digits come out wrong or as arrows/navigation, flip USE_NUMPAD below.

import time

import board
import digitalio
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keycode import Keycode

SECRET_PATH = "/blm_secret.txt"
ARM_DELAY_S = 4.0          # seconds to wait after power-up before typing (focus the field)
KEY_DELAY_S = 0.012        # gap between keystrokes

# False = top-row number keys (no NumLock needed) — the safe default.
# True  = numpad keys (needs NumLock ON, but layout-independent). Try this only if
#         top-row digits come out wrong at your recovery screen.
USE_NUMPAD = False

LED = digitalio.DigitalInOut(board.LED)
LED.direction = digitalio.Direction.OUTPUT

TOPROW = {
    "0": Keycode.ZERO, "1": Keycode.ONE, "2": Keycode.TWO, "3": Keycode.THREE,
    "4": Keycode.FOUR, "5": Keycode.FIVE, "6": Keycode.SIX, "7": Keycode.SEVEN,
    "8": Keycode.EIGHT, "9": Keycode.NINE,
}
NUMPAD = {
    "0": Keycode.KEYPAD_ZERO, "1": Keycode.KEYPAD_ONE, "2": Keycode.KEYPAD_TWO,
    "3": Keycode.KEYPAD_THREE, "4": Keycode.KEYPAD_FOUR, "5": Keycode.KEYPAD_FIVE,
    "6": Keycode.KEYPAD_SIX, "7": Keycode.KEYPAD_SEVEN, "8": Keycode.KEYPAD_EIGHT,
    "9": Keycode.KEYPAD_NINE,
}
DIGITS = NUMPAD if USE_NUMPAD else TOPROW
ENTER = Keycode.KEYPAD_ENTER if USE_NUMPAD else Keycode.ENTER


def read_key():
    try:
        with open(SECRET_PATH) as f:
            return "".join(ch for ch in f.read() if ch.isdigit())
    except OSError:
        return ""


def blink(n, dt=0.15):
    for _ in range(n):
        LED.value = True; time.sleep(dt); LED.value = False; time.sleep(dt)


def main():
    key = read_key()
    if not key:
        blink(2)              # nothing loaded — do nothing
        return
    blink(3)                  # armed
    time.sleep(ARM_DELAY_S)   # let the operator focus the recovery field

    kbd = Keyboard(usb_hid.devices)
    for digit in key:
        kc = DIGITS.get(digit)
        if kc is not None:
            kbd.send(kc)
            time.sleep(KEY_DELAY_S)
    kbd.send(ENTER)
    LED.value = True          # solid = done


main()
