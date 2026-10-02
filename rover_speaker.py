"""
Brookstone Rover Revolution - speaker ("talk") support for Python.

The Rover Revolution is a WiFi-controlled spy rover (SSID like
``RoverRev00E04C0D9EE0``, TCP 192.168.1.100:80). The base command protocol
(auth, drive, turret, video) was documented by fabus1184/rover-revolution;
this module adds the two-way-audio *talk* protocol, which lets the rover
play audio through its built-in speaker.

Talk protocol summary (see README.md for the full write-up):

* The rover's speaker stays silent unless an audio/video (AV) session is
  already up: call :meth:`Rover.start_video` and :meth:`Rover.start_audio`
  before :meth:`Rover.talk_start`.
* Talk mode is half-duplex: the microphone stream stops while talking.
* After the rover acknowledges talk mode, open a second TCP socket and
  send a 12-byte handshake: u64 little-endian buffer size, then the
  bytes 7, 1, 16, 1.
* Stream raw IMA ADPCM (44100 Hz, mono) paced in real time; the rover's
  speaker pipeline stalls if you blast data at full speed.
* Keep clips to ~4-5 seconds; longer streams get cut off.
* End with the talk-end command and wait for its acknowledgement.

Example:
    rover = Rover()
    rover.connect()
    rover.start_video()
    rover.start_audio()
    rover.talk_say_wav("hello.wav")  # 44100 Hz mono 16-bit WAV
    rover.disconnect()

Requires: pycryptodome (for the Blowfish-LE auth handshake).
"""

import socket
import struct
import time
import threading
import wave

ROVER_IP = "192.168.1.100"
ROVER_PORT = 80

# Default credentials used by the official app.
TARGET_ID = "AC13"
TARGET_PASSWORD = "AC13"


# ---------------------------------------------------------------------------
# IMA ADPCM codec (standard algorithm, per IMA Recommended Practices).
#
# The rover's talk channel carries IMA ADPCM at 44100 Hz mono: 4 bits per
# sample, packed two samples per byte (low nibble first). Encoder state
# (predicted sample + step-table index) carries across encode() calls for
# the duration of one talk session.
# ---------------------------------------------------------------------------

_IMA_STEP_TABLE = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37,
    41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173,
    190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658,
    724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
    2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894,
    6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289,
    16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
]
_IMA_INDEX_TABLE = [-1, -1, -1, -1, 2, 4, 6, 8]


class ImaAdpcmEncoder:
    """Stateful IMA ADPCM encoder: 16-bit PCM mono -> 4-bit ADPCM."""

    def __init__(self):
        self._predicted = 0
        self._index = 0

    def encode(self, pcm: bytes) -> bytes:
        """Encode 16-bit little-endian mono PCM bytes to IMA ADPCM bytes."""
        sample_count = len(pcm) // 2
        out = bytearray((sample_count + 1) // 2)
        predicted = self._predicted
        index = self._index
        out_pos = 0
        for i in range(sample_count):
            sample = struct.unpack_from("<h", pcm, i * 2)[0]
            diff = sample - predicted
            sign = 0x08 if diff < 0 else 0x00
            if sign:
                diff = -diff
            step = _IMA_STEP_TABLE[index]
            delta = 0
            vpdiff = step >> 3
            if diff >= step:
                delta |= 0x04
                diff -= step
                vpdiff += step
            if diff >= (step >> 1):
                delta |= 0x02
                diff -= step >> 1
                vpdiff += step >> 1
            if diff >= (step >> 2):
                delta |= 0x01
                vpdiff += step >> 2
            predicted = predicted - vpdiff if sign else predicted + vpdiff
            predicted = max(-32768, min(32767, predicted))
            code = delta | sign
            index = max(0, min(88, index + _IMA_INDEX_TABLE[delta]))
            if i & 1:
                out[out_pos] |= code & 0x0F
                out_pos += 1
            else:
                out[out_pos] = (code << 4) & 0xF0
        self._predicted = predicted
        self._index = index
        return bytes(out[:out_pos])


class ImaAdpcmDecoder:
    """Stateful IMA ADPCM decoder: 4-bit ADPCM -> 16-bit PCM mono bytes."""

    def __init__(self):
        self._predicted = 0
        self._index = 0

    def decode(self, data: bytes) -> bytes:
        out = bytearray()
        for i in range(len(data) * 2):
            byte = data[i >> 1]
            code = (byte & 0x0F) if (i & 1) else (byte >> 4)
            sign = code & 0x08
            magnitude = code & 0x07
            step = _IMA_STEP_TABLE[self._index]
            diff = (step * magnitude) // 4 + (step >> 3)
            if sign:
                diff = -diff
            self._predicted = max(-32768, min(32767, self._predicted + diff))
            out += struct.pack("<h", self._predicted)
            self._index = max(0, min(88, self._index + _IMA_INDEX_TABLE[magnitude]))
        return bytes(out)


# ---------------------------------------------------------------------------
# Protocol framing (command socket).
# ---------------------------------------------------------------------------

def _build_request(channel: int, cmd_id: int, payload: bytes) -> bytes:
    header = (bytes([0x4D, 0x4F, 0x5F, channel, cmd_id]) + bytes(10)
              + bytes([len(payload)]) + bytes(7))
    assert len(header) == 23
    return header + payload


def _req_command(cmd_id: int, payload: bytes) -> bytes:
    return _build_request(0x4F, cmd_id, payload)


def _req_u32s(cmd_id: int, values) -> bytes:
    payload = b"".join(struct.pack("<I", v & 0xFFFFFFFF) for v in values)
    return _req_command(cmd_id, payload)


# ---------------------------------------------------------------------------
# Blowfish-LE auth (the rover packs Blowfish words little-endian; emulate
# with standard Blowfish plus byte-swapping).
# ---------------------------------------------------------------------------

try:
    from Crypto.Cipher import Blowfish as _Blowfish
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False


def _blowfish_le_encrypt(key: bytes, block8: bytes) -> bytes:
    assert len(block8) == 8
    if not _HAS_CRYPTO:
        raise RuntimeError("pycryptodome is required: pip install pycryptodome")
    left, right = struct.unpack("<II", block8)
    cipher = _Blowfish.new(key, _Blowfish.MODE_ECB)
    enc = cipher.encrypt(struct.pack(">II", left, right))
    left2, right2 = struct.unpack(">II", enc)
    return struct.pack("<II", left2, right2)


# Command opcodes used here.
_CMD_AUTH_INIT = 0
_CMD_AUTH_RESP = 2
_CMD_VIDEO_START = 4
_CMD_AUDIO_START = 8
_CMD_TALK_START = 11
_CMD_TALK_END = 13
_RESP_VIDEO_START = 5
_RESP_AUDIO_START = 9
_RESP_TALK_START = 12
_RESP_TALK_END = 22


class Rover:
    """Connection to a Rover Revolution, with speaker (talk) support."""

    def __init__(self, ip: str = ROVER_IP, port: int = ROVER_PORT):
        self.ip = ip
        self.port = port
        self._cmd = None
        self._media = None
        self._talk = None
        self._hb_stop = threading.Event()
        self._hb_thread = None

    # -- low-level helpers -------------------------------------------------

    @staticmethod
    def _recv_exact(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("socket closed")
            buf += chunk
        return buf

    def _read_cmd_packet(self, timeout: float = 8):
        """Read one command-socket reply; returns (opcode, payload)."""
        self._cmd.settimeout(timeout)
        try:
            hdr = self._recv_exact(self._cmd, 23)
        finally:
            self._cmd.settimeout(10)
        if hdr[0:4] != b"MO_O":
            raise RuntimeError(f"bad command header: {hdr[0:4]!r}")
        opcode = struct.unpack("<H", hdr[4:6])[0]
        length = struct.unpack("<i", hdr[15:19])[0]
        payload = self._recv_exact(self._cmd, length) if length > 0 else b""
        return opcode, payload

    # -- session setup -----------------------------------------------------

    def connect(self) -> bool:
        """Run the challenge/response auth handshake and start heartbeats."""
        self._cmd = socket.create_connection((self.ip, self.port), timeout=10)
        self._cmd.settimeout(10)

        self._cmd.sendall(_req_u32s(_CMD_AUTH_INIT, [0, 0, 0, 0]))
        reply = self._recv_exact(self._cmd, 82)

        camera_id = reply[25:37].decode("utf-8", errors="replace").strip("\x00")
        l1, r1, l2, r2 = struct.unpack("<iiii", reply[66:82])

        key = f"{TARGET_ID}:{camera_id}-save-private:{TARGET_PASSWORD}".encode()
        e1 = _blowfish_le_encrypt(key, struct.pack("<ii", l1, r1))
        e2 = _blowfish_le_encrypt(key, struct.pack("<ii", l2, r2))
        el1, er1 = struct.unpack("<II", e1)
        el2, er2 = struct.unpack("<II", e2)
        self._cmd.sendall(_req_u32s(_CMD_AUTH_RESP, [el1, er1, el2, er2]))
        # Auth reply: 23-byte header + 6-byte payload (29 bytes total).
        # Reading fewer leaves stray bytes that desync later packet parsing.
        self._recv_exact(self._cmd, 29)

        self._hb_stop.clear()
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._hb_thread.start()
        print(f"[rover] connected (camera_id={camera_id})", flush=True)
        return True

    def _heartbeat_loop(self):
        while not self._hb_stop.wait(30):
            try:
                self._cmd.sendall(_req_command(0xFF, b""))
            except OSError:
                break

    def start_video(self):
        """Bring up the video stream. Required before talk mode."""
        self._cmd.sendall(_req_u32s(_CMD_VIDEO_START, [1]))
        opcode, payload = self._read_cmd_packet()
        if opcode != _RESP_VIDEO_START:
            raise RuntimeError(f"expected video-start reply (5), got {opcode}")
        link_id = payload[2:6] if len(payload) >= 6 else b"\x00\x00\x00\x00"
        self._media = socket.create_connection((self.ip, self.port), timeout=10)
        self._media.settimeout(10)
        self._media.sendall(_build_request(0x56, 0, link_id))
        return self._media

    def start_audio(self):
        """Enable the rover microphone stream. Call after start_video()."""
        self._cmd.sendall(_req_command(_CMD_AUDIO_START, bytes([1])))
        opcode, payload = self._read_cmd_packet()
        if opcode != _RESP_AUDIO_START:
            raise RuntimeError(f"expected audio-start reply (9), got {opcode}")
        return payload

    # -- speaker / talk ----------------------------------------------------

    def talk_start(self, timeout: float = 8) -> bool:
        """Ask the rover to enter talk mode. True if it acknowledged."""
        self._cmd.sendall(_req_command(_CMD_TALK_START, bytes([1])))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                opcode, _ = self._read_cmd_packet(
                    timeout=max(1.0, deadline - time.time()))
            except (socket.timeout, ConnectionError, OSError):
                break
            if opcode == _RESP_TALK_START:
                print("[rover] talk mode accepted", flush=True)
                return True
            # ignore anything else (e.g. heartbeat replies)
        print("[rover] talk mode not acknowledged", flush=True)
        return False

    def talk_open(self):
        """Open the dedicated talk socket and send the 12-byte handshake:
        u64 little-endian buffer size, then bytes 7, 1, 16, 1."""
        sock = socket.create_connection((self.ip, self.port), timeout=10)
        sock.sendall(struct.pack("<Q", 8192) + bytes([7, 1, 16, 1]))
        self._talk = sock
        return sock

    def talk_stream(self, sock, pcm44100: bytes, chunk_samples: int = 4096):
        """Encode 44100 Hz mono 16-bit PCM to ADPCM and stream it.

        Data is paced in real time: the rover's speaker pipeline stalls
        if you send faster than it can play.
        """
        enc = ImaAdpcmEncoder()
        step = chunk_samples * 2
        chunk_dur = chunk_samples / 44100.0
        t_next = time.time() + chunk_dur
        for off in range(0, len(pcm44100), step):
            chunk = pcm44100[off:off + step]
            if len(chunk) % 2:
                chunk += b"\x00"
            sock.sendall(enc.encode(chunk))
            delay = t_next - time.time()
            if delay > 0:
                time.sleep(delay)
            t_next += chunk_dur

    def talk_stop(self, timeout: float = 5):
        """Leave talk mode, retrying until the rover acknowledges."""
        self._cmd.sendall(_req_command(_CMD_TALK_END, b""))
        deadline = time.time() + timeout
        tries = 0
        while time.time() < deadline and tries < 10:
            try:
                opcode, _ = self._read_cmd_packet(timeout=0.4)
            except (socket.timeout, ConnectionError, OSError):
                opcode = None
            if opcode == _RESP_TALK_END:
                print("[rover] talk mode ended", flush=True)
                break
            tries += 1
            self._cmd.sendall(_req_command(_CMD_TALK_END, b""))
            time.sleep(0.3)
        try:
            if self._talk:
                self._talk.close()
        except OSError:
            pass
        self._talk = None

    def talk_say_pcm(self, pcm44100: bytes):
        """Full talk pipeline for 44100 Hz mono 16-bit PCM bytes."""
        if not self.talk_start():
            raise RuntimeError("rover did not accept talk mode")
        try:
            sock = self.talk_open()
            self.talk_stream(sock, pcm44100)
        finally:
            self.talk_stop()

    def talk_say_wav(self, path: str):
        """Play a WAV file through the rover speaker.

        The WAV must be 44100 Hz, mono, 16-bit. (Convert e.g. with:
        ``ffmpeg -i in.mp3 -ar 44100 -ac 1 -sample_fmt s16 out.wav``)
        """
        with wave.open(path, "rb") as w:
            if (w.getframerate(), w.getnchannels(), w.getsampwidth()) != (44100, 1, 2):
                raise ValueError("WAV must be 44100 Hz mono 16-bit")
            pcm = w.readframes(w.getnframes())
        self.talk_say_pcm(pcm)

    def disconnect(self):
        self._hb_stop.set()
        for sock in (self._cmd, self._media, self._talk):
            try:
                if sock:
                    sock.close()
            except OSError:
                pass
        self._talk = None
        print("[rover] disconnected", flush=True)
