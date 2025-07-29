import sys
import time
import threading
from itertools import cycle

def spinner_animation(stop_event, message="Loading"):
    """Display a spinner animation with a message"""
    spinner = cycle(['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'])
    while not stop_event.is_set():
        sys.stdout.write(f'\r{message} {next(spinner)} ')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r')
    sys.stdout.flush()

def start_spinner(message="Loading"):
    """Start the spinner animation in a separate thread"""
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner_animation, args=(stop_event, message))
    spinner_thread.start()
    return stop_event, spinner_thread

def stop_spinner(stop_event, spinner_thread):
    """Stop the spinner animation"""
    stop_event.set()
    spinner_thread.join()

def typing_print(text, delay=0.03):
    """Print text with a typewriter effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def clear_screen():
    """Clear the terminal screen"""
    print("\033[H\033[J", end="")

def print_with_effect(text, effect="fade"):
    """Print text with various effects"""
    if effect == "fade":
        for line in text.split('\n'):
            print(line)
            time.sleep(0.05)
    elif effect == "typewriter":
        typing_print(text)
