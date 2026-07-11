"""ESPHome Noise-encrypted Native API transport (server side).

This implements the *server* half of the encrypted transport that Home
Assistant (via aioesphomeapi) speaks when an ESPHome device is configured with
``api: encryption: key:``.

The wire format here is a **fixed external contract**. It was taken from
``esphome/components/api/api_frame_helper_noise.cpp`` and
``aioesphomeapi/_frame_helper/noise.py`` -- not from memory of the Noise spec.
Byte-for-byte interoperability with a stock Home Assistant is the entire point,
so none of these constants may be "improved":

* Frame:        ``0x01`` indicator byte, 16-bit **big-endian** length, payload.
* Client hello: an empty frame -- literally the three bytes ``01 00 00``.
* Prologue:     ``b"NoiseAPIInit"`` + uint16be(len(hello_body)) + hello_body,
                which for the (always empty in practice) client hello body is
                exactly ``b"NoiseAPIInit\\x00\\x00"``.
* Server hello: ``0x01`` (chosen protocol) + name + NUL + mac + NUL.
* Handshake payloads carry a status prefix: ``0x00`` success, ``0x01`` failure
  followed by a short human-readable reason.
* Inner header (inside the encrypted box): 4 bytes big-endian,
  ``[type_hi][type_lo][len_hi][len_lo]``, then the protobuf payload.

The PSK is 32 raw bytes and is never logged, at any level.
"""

from __future__ import annotations

import asyncio
import logging

from cryptography.exceptions import InvalidTag
from noise.connection import NoiseConnection

logger = logging.getLogger(__name__)

# --- Wire protocol constants (external contract -- do not change) -----------

NOISE_PROTOCOL_NAME = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"

#: Value advertised in the mDNS ``api_encryption`` TXT record.
API_ENCRYPTION_NAME = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"

INDICATOR = 0x01
PROLOGUE_INIT = b"NoiseAPIInit"
CHOSEN_PROTO = 0x01

HANDSHAKE_OK = 0x00
HANDSHAKE_FAILURE = 0x01
MAC_FAILURE_REASON = b"Handshake MAC failure"
GENERIC_FAILURE_REASON = b"Handshake error"

PSK_LENGTH = 32
AEAD_TAG_LEN = 16
INNER_HEADER_LEN = 4

#: A Noise transport message (the ciphertext) may not exceed 65535 bytes, which
#: is also the largest length the 16-bit frame header can express.
MAX_FRAME_LEN = 65535
#: Largest plaintext that still fits once the 16-byte AEAD tag is appended.
MAX_PLAINTEXT_LEN = MAX_FRAME_LEN - AEAD_TAG_LEN
#: Largest protobuf payload, after the 4-byte inner header is accounted for.
MAX_MESSAGE_LEN = MAX_PLAINTEXT_LEN - INNER_HEADER_LEN


class NoiseError(Exception):
    """Base class for errors raised by this transport."""


class NoiseHandshakeError(NoiseError):
    """The Noise handshake could not be completed (e.g. a wrong PSK)."""


# --- Pure framing helpers (unit-testable without any I/O) -------------------


def encode_frame(payload: bytes) -> bytes:
    """Frame a payload: ``0x01`` + uint16be(len) + payload."""
    length = len(payload)
    if length > MAX_FRAME_LEN:
        raise ValueError(
            f"Noise frame payload of {length} bytes exceeds the "
            f"{MAX_FRAME_LEN}-byte transport limit"
        )
    return bytes((INDICATOR, (length >> 8) & 0xFF, length & 0xFF)) + payload


def build_prologue(hello_body: bytes) -> bytes:
    """Build the Noise prologue from the client hello frame body.

    ``b"NoiseAPIInit"`` + uint16be(len(body)) + body. The client hello body is
    empty in practice, so this is normally ``b"NoiseAPIInit\\x00\\x00"``.
    """
    length = len(hello_body)
    return (
        PROLOGUE_INIT + bytes(((length >> 8) & 0xFF, length & 0xFF)) + hello_body
    )


def build_server_hello(name: str, mac: str) -> bytes:
    """Server hello payload: chosen proto + name + NUL + mac + NUL."""
    return (
        bytes((CHOSEN_PROTO,))
        + name.encode("utf-8")
        + b"\x00"
        + mac.encode("utf-8")
        + b"\x00"
    )


def encode_inner(msg_type: int, data: bytes) -> bytes:
    """Build the plaintext that goes inside the encrypted box.

    4-byte big-endian header ``[type_hi][type_lo][len_hi][len_lo]`` + payload.
    """
    length = len(data)
    if length > MAX_MESSAGE_LEN:
        raise ValueError(
            f"Message of {length} bytes exceeds the maximum encryptable payload "
            f"of {MAX_MESSAGE_LEN} bytes (Noise 65535-byte transport limit, "
            f"less the {AEAD_TAG_LEN}-byte AEAD tag and the "
            f"{INNER_HEADER_LEN}-byte header)"
        )
    return (
        bytes(
            (
                (msg_type >> 8) & 0xFF,
                msg_type & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            )
        )
        + data
    )


def decode_inner(plaintext: bytes) -> tuple[int, bytes]:
    """Parse a decrypted transport message into ``(msg_type, payload)``.

    The inner length field is deliberately **ignored**: we trust the frame
    length instead, exactly as aioesphomeapi does, rather than a length field
    the peer controls.
    """
    if len(plaintext) < INNER_HEADER_LEN:
        raise ValueError(
            f"Decrypted message too short: {len(plaintext)} bytes"
        )
    msg_type = (plaintext[0] << 8) | plaintext[1]
    return msg_type, plaintext[INNER_HEADER_LEN:]


# --- The transport ----------------------------------------------------------


class NoiseFrameHelper:
    """Server side of the ESPHome Noise transport over an asyncio stream pair.

    Constructed with the stream reader/writer of an accepted connection, the
    32-byte PSK, and the node name and MAC to advertise in the server hello.
    Call :meth:`perform_handshake` once, then use :meth:`read_message` and
    :meth:`write_message`.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        psk: bytes,
        server_name: str,
        mac: str,
    ) -> None:
        if len(psk) != PSK_LENGTH:
            # Deliberately reports only the length -- never the key material.
            raise ValueError(
                f"PSK must be exactly {PSK_LENGTH} bytes, got {len(psk)}"
            )
        self._reader = reader
        self._writer = writer
        self._psk = psk
        self._server_name = server_name
        self._mac = mac
        self._proto: NoiseConnection | None = None
        self._handshake_complete = False
        self._closed = False
        self._peer = writer.get_extra_info("peername", ("unknown", 0))

    @property
    def handshake_complete(self) -> bool:
        return self._handshake_complete

    # -- frame I/O ----------------------------------------------------------

    async def _read_frame(self) -> bytes:
        """Read one ``0x01``-indicator frame. Raises on a bad indicator."""
        header = await self._reader.readexactly(3)
        if header[0] != INDICATOR:
            raise NoiseError(f"Invalid frame indicator byte: 0x{header[0]:02x}")
        length = (header[1] << 8) | header[2]
        if length == 0:
            return b""
        return await self._reader.readexactly(length)

    def _write_frame(self, payload: bytes) -> None:
        if self._closed:
            return
        self._writer.write(encode_frame(payload))

    async def drain(self) -> None:
        """Flush the write buffer."""
        if self._closed:
            return
        await self._writer.drain()

    # -- handshake ----------------------------------------------------------

    async def perform_handshake(self) -> None:
        """Run the server side of the hello exchange and the Noise handshake.

        On a PSK mismatch an explicit rejection frame (``0x01`` +
        ``"Handshake MAC failure"``) is sent *before* raising, so that Home
        Assistant can tell the user their encryption key is wrong instead of
        showing an opaque timeout.
        """
        # 1. Client hello. ESPHome ignores the body ("may be used in future for
        #    flags") but it is fed into the prologue, so it must be captured.
        hello_body = await self._read_frame()
        prologue = build_prologue(hello_body)

        # 2. Server hello.
        self._write_frame(build_server_hello(self._server_name, self._mac))
        await self.drain()

        # 3. Noise session as the responder.
        proto = NoiseConnection.from_name(NOISE_PROTOCOL_NAME)
        proto.set_as_responder()
        proto.set_psks(self._psk)
        proto.set_prologue(prologue)
        proto.start_handshake()
        self._proto = proto

        # 4. Client handshake frame: status byte + noise message.
        msg = await self._read_frame()
        if not msg:
            self._send_handshake_reject(b"Empty handshake message")
            raise NoiseHandshakeError("Client sent an empty handshake message")
        if msg[0] != HANDSHAKE_OK:
            self._send_handshake_reject(b"Bad handshake error byte")
            raise NoiseHandshakeError(
                f"Client handshake status byte was 0x{msg[0]:02x}, expected 0x00"
            )

        try:
            proto.read_message(msg[1:])
        except InvalidTag as err:
            # Wrong PSK: the AEAD tag on the client's handshake message does
            # not authenticate. This is the case Home Assistant must be told
            # about explicitly.
            self._send_handshake_reject(MAC_FAILURE_REASON)
            raise NoiseHandshakeError(
                "Handshake MAC failure (client used the wrong encryption key)"
            ) from err
        except Exception as err:  # noqa: BLE001 - any malformed handshake
            self._send_handshake_reject(GENERIC_FAILURE_REASON)
            raise NoiseHandshakeError(f"Handshake failed: {err}") from err

        # 5. Server handshake reply, prefixed with the success status byte.
        self._write_frame(bytes((HANDSHAKE_OK,)) + proto.write_message())
        await self.drain()

        if not proto.handshake_finished:
            raise NoiseHandshakeError(
                "Noise handshake did not complete after the server reply"
            )
        self._handshake_complete = True
        logger.debug("Noise handshake complete with %s", self._peer)

    def _send_handshake_reject(self, reason: bytes) -> None:
        """Send the explicit rejection frame ESPHome sends: 0x01 + reason."""
        try:
            self._write_frame(bytes((HANDSHAKE_FAILURE,)) + reason)
        except Exception:  # noqa: BLE001 - best effort; we are closing anyway
            logger.debug("Could not send handshake rejection to %s", self._peer)

    # -- transport ----------------------------------------------------------

    async def read_message(self) -> tuple[int, bytes]:
        """Read, decrypt and parse one transport message."""
        if not self._handshake_complete or self._proto is None:
            raise NoiseError("read_message() before the handshake completed")
        frame = await self._read_frame()
        try:
            plaintext = self._proto.decrypt(frame)
        except InvalidTag as err:
            raise NoiseError("Failed to decrypt frame") from err
        return decode_inner(plaintext)

    def write_message(self, msg_type: int, data: bytes) -> None:
        """Encrypt and frame one message. Raises ValueError if it is too big."""
        if not self._handshake_complete or self._proto is None:
            raise NoiseError("write_message() before the handshake completed")
        if self._closed:
            return
        # encode_inner enforces the 65535-byte ceiling on the resulting
        # ciphertext (plaintext + the 16-byte AEAD tag) rather than truncating.
        plaintext = encode_inner(msg_type, data)
        self._write_frame(self._proto.encrypt(plaintext))

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._writer.close()
        except Exception:  # noqa: BLE001 - already going away
            pass
