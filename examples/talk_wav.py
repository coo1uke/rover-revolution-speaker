"""Play a WAV file through the Rover Revolution's speaker.

Usage:
    python talk_wav.py hello.wav

The WAV must be 44100 Hz, mono, 16-bit. Convert with e.g.:
    ffmpeg -i in.mp3 -ar 44100 -ac 1 -sample_fmt s16 out.wav

Join the rover's WiFi AP before running.
"""
import sys

sys.path.insert(0, "..")
from rover_speaker import Rover


def main(path: str):
    rover = Rover()
    try:
        rover.connect()
        rover.start_video()
        rover.start_audio()
        rover.talk_say_wav(path)
    finally:
        rover.disconnect()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python talk_wav.py <file.wav>")
        raise SystemExit(1)
    main(sys.argv[1])
