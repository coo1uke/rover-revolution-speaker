# Rover Revolution speaker ("talk") support

Python support for the **speaker** on the Brookstone Rover Revolution
(WiFi spy rover). The base command protocol — auth, driving, turret,
video — was reverse-engineered by
[fabus1184/rover-revolution](https://github.com/fabus1184/rover-revolution);
this repo documents and implements the **two-way-audio talk protocol**,
which lets you play audio through the rover's built-in speaker.

Tested against a real unit (firmware as shipped; SSID `RoverRev00E04C0D9EE0`,
TCP `192.168.1.100:80`).

## Quick start

```bash
pip install -r requirements.txt
# join the rover's WiFi AP first, then:
ffmpeg -i hello.mp3 -ar 44100 -ac 1 -sample_fmt s16 hello.wav
python examples/talk_wav.py hello.wav
```

or in your own code:

```python
from rover_speaker import Rover

rover = Rover()
rover.connect()
rover.start_video()
rover.start_audio()
rover.talk_say_wav("hello.wav")  # 44100 Hz mono 16-bit WAV
rover.disconnect()
```

## The talk protocol

Observed by studying the official app's behavior (command opcodes in
parentheses are the command-socket values):

1. **AV session first.** The speaker stays *completely silent* unless a
   video + audio session is already up. Call video-start (4) and
   audio-start (8) before talk-start (11) — otherwise talk mode is
   accepted and the audio is consumed, but nothing plays.
2. **Half-duplex.** The microphone stream stops while talk mode is
   active; it resumes afterwards.
3. **Talk-start handshake.** Send talk-start (11) with payload `[1]`;
   the rover replies with talk-start-resp (12).
4. **Dedicated socket + 12-byte handshake.** Open a second TCP
   connection to port 80 and send: u64 little-endian buffer size
   (8192, matching a 44100 Hz mono 16-bit capture buffer), then the
   bytes `7, 1, 16, 1`.
5. **Stream raw IMA ADPCM.** Audio is IMA ADPCM, 44100 Hz mono
   (4 bits/sample, two samples per byte, low nibble first). Stream it
   **paced in real time** — the rover's speaker pipeline stalls and its
   TCP window wedges if you send faster than it plays.
6. **Keep clips short.** Streams much longer than ~4–5 seconds get cut
   off (the connection is reset after ~120 KB / ~5.5 s of audio).
7. **Talk-end.** Send talk-end (13), retrying until talk-end-resp (22)
   arrives, then close the talk socket.

There is no rover-side speaker-volume command; volume is fixed.

## Files

| File | What it is |
|---|---|
| `rover_speaker.py` | Self-contained client: auth, video/audio start, full talk pipeline, standard IMA ADPCM codec |
| `examples/talk_wav.py` | Play a WAV file through the rover speaker |
| `requirements.txt` | `pycryptodome` (Blowfish-LE auth handshake) |

## Notes

- The IMA ADPCM codec here is a standard implementation of the IMA
  Recommended Practices algorithm, written from the public spec.
- Drive-gear note: many surviving units (including the one tested)
  have stripped drive gears and can't move — the turret, camera, mic,
  and speaker all still work.

## License

MIT — see [LICENSE](LICENSE).
