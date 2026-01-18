"""High-level sans-io client for composing ShiningRGB protocol operations.

This module provides a convenience layer that composes low-level protocol operations
into common high-level operations like uploading images or switching modes. It remains
strictly sans-io - all I/O operations must be performed by the caller.
"""

from __future__ import annotations

from pyshiningrgb.builders import (
    build_apply_attributes,
    build_data_transfer_auto,
    build_library_load,
    build_mode_select,
    build_set_attributes,
    build_transfer_complete,
)
from pyshiningrgb.semantic import AnimationType, RenderMode


class ImageUploadSequence:
    """Represents a complete image upload operation as a sequence of messages.

    This class composes all the messages needed to upload an image to the device,
    including mode selection, library loading, data transfer, and completion.
    """

    def __init__(
        self,
        width: int,
        height: int,
        pixel_data: bytes,
        unknown_header: bytes = b"\x00\x00\x00\x00",
        animation_type: AnimationType = AnimationType.NONE,
        background_color: bytes = b"\x00\x00",
        animation_speed: int = 0,
    ) -> None:
        """Initialize an image upload sequence.

        Args:
            width: Image width in pixels (max 0x3a = 58)
            height: Image height in pixels (max 0x50 = 80)
            pixel_data: RGB565 pixel data (2 bytes per pixel, little-endian)
            unknown_header: Unknown 4 bytes in data transfer header (default: 0x00 0x00 0x00 0x00)
            animation_type: Animation type for display (default: NONE)
            background_color: Background color in RGB565 format (2 bytes, little-endian)
            animation_speed: Animation speed from 0 (slowest) to 10 (fastest)

        Raises:
            ValueError: If dimensions exceed limits or animation_speed out of range
        """
        self.width = width
        self.height = height
        self.pixel_data = pixel_data
        self.unknown_header = unknown_header
        self.animation_type = animation_type
        self.background_color = background_color
        self.animation_speed = animation_speed
        self._messages: list[tuple[str, bytes]] = []
        self._build_messages()

    def _build_messages(self) -> None:
        """Build all messages for the upload sequence."""
        # Select TEXT rendering mode
        self._messages.append(("Select TEXT rendering mode", build_mode_select(RenderMode.TEXT)))

        # Load Text.lib library
        self._messages.append(
            ("Load /Text.lib library", build_library_load("/Text.lib", 0x48, 0x15))
        )

        # Auto-chunk the data transfer
        data_messages = build_data_transfer_auto(
            self.width, self.height, self.pixel_data, self.unknown_header
        )
        self._messages.extend(data_messages)

        # Signal transfer complete
        self._messages.append(("Transfer complete", build_transfer_complete()))

        # Set display attributes (animation type, speed, background color)
        self._messages.append(
            (
                f"Set attributes (animation={self.animation_type.name}, speed={self.animation_speed})",
                build_set_attributes(
                    self.animation_type,
                    background_color=self.background_color,
                    animation_speed=self.animation_speed,
                ),
            )
        )

        # Apply attributes (end of message marker)
        self._messages.append(("Apply attributes (EOM)", build_apply_attributes()))

    def messages(self) -> list[tuple[str, bytes]]:
        """Get the sequence of messages to send.

        Returns:
            List of (description, message_bytes) tuples in order
        """
        return self._messages

    def __len__(self) -> int:
        """Get the number of messages in the sequence."""
        return len(self._messages)

    def __iter__(self):
        """Iterate over messages in the sequence."""
        return iter(self._messages)


class ShiningRGBClient:
    """Sans-io client for composing ShiningRGB protocol operations.

    This client helps compose sequences of protocol messages for common operations
    without performing any I/O. The caller is responsible for sending messages and
    receiving responses over their chosen transport.

    Example:
        >>> client = ShiningRGBClient()
        >>> upload = client.prepare_image_upload(58, 80, pixel_data)
        >>> for description, message in upload:
        ...     sock.send(message)
        ...     response = sock.recv(1024)  # Handle response as needed
    """

    def prepare_image_upload(
        self,
        width: int,
        height: int,
        pixel_data: bytes,
        unknown_header: bytes = b"\x00\x00\x00\x00",
        animation_type: AnimationType = AnimationType.NONE,
        background_color: bytes = b"\x00\x00",
        animation_speed: int = 0,
    ) -> ImageUploadSequence:
        """Prepare all messages needed to upload an image.

        Args:
            width: Image width in pixels (max 0x3a = 58)
            height: Image height in pixels (max 0x50 = 80)
            pixel_data: RGB565 pixel data (2 bytes per pixel, little-endian)
            unknown_header: Unknown 4 bytes in data transfer header
            animation_type: Animation type for display (default: NONE)
            background_color: Background color in RGB565 format (2 bytes, little-endian)
            animation_speed: Animation speed from 0 (slowest) to 10 (fastest)

        Returns:
            ImageUploadSequence containing all messages to send

        Raises:
            ValueError: If dimensions exceed limits or data size is incorrect
        """
        expected_size = width * height * 2  # 2 bytes per pixel (RGB565)
        if len(pixel_data) != expected_size:
            raise ValueError(
                f"Pixel data size mismatch: expected {expected_size} bytes "
                f"for {width}x{height} image, got {len(pixel_data)}"
            )

        return ImageUploadSequence(
            width,
            height,
            pixel_data,
            unknown_header,
            animation_type,
            background_color,
            animation_speed,
        )

    def prepare_mode_switch(self, mode: RenderMode) -> list[tuple[str, bytes]]:
        """Prepare messages to switch rendering mode.

        Args:
            mode: Target rendering mode

        Returns:
            List of (description, message_bytes) tuples
        """
        return [(f"Switch to mode {mode.name}", build_mode_select(mode))]

    def prepare_library_load(
        self,
        path: str,
        unknown1: int = 0x48,
        unknown2: int = 0x15,
        unknown3: bytes = b"\x00\x00",
    ) -> list[tuple[str, bytes]]:
        """Prepare messages to load a library.

        Args:
            path: Library path (e.g., "/Text.lib")
            unknown1: Unknown byte (default 0x48)
            unknown2: Unknown byte (default 0x15)
            unknown3: Unknown 2 bytes (default 0x00 0x00)

        Returns:
            List of (description, message_bytes) tuples
        """
        return [
            (
                f"Load library {path}",
                build_library_load(path, unknown1, unknown2, unknown3),
            )
        ]
