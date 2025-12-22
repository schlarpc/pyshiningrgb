"""pyshiningrgb - Sans-io library for ShiningRGB LED mask control protocol.

This library provides a pure sans-io implementation of the ShiningRGB WiFi control
protocol for LED masks, along with a reference CLI implementation.

Example:
    >>> from pyshiningrgb import ShiningRGBClient
    >>> client = ShiningRGBClient()
    >>> # Generate pixel data (58x80 RGB565)
    >>> pixel_data = bytes(58 * 80 * 2)  # Your image data here
    >>> # Prepare upload sequence
    >>> upload = client.prepare_image_upload(58, 80, pixel_data)
    >>> # Send messages over your transport
    >>> for description, message in upload:
    ...     sock.send(message)
"""

import importlib.metadata as _importlib_metadata

from pyshiningrgb.builders import (
    build_data_transfer_auto,
    build_data_transfer_chunk,
    build_data_transfer_first_chunk,
    build_library_load,
    build_method_06,
    build_method_09,
    build_method_0a,
    build_mode_select,
    build_transfer_complete,
)
from pyshiningrgb.client import ImageUploadSequence, ShiningRGBClient
from pyshiningrgb.protocol import (
    MAX_C2S_PAYLOAD,
    MAX_MESSAGE_SIZE,
    MAX_S2C_PAYLOAD,
    Direction,
    build_c2s_message,
    build_s2c_message,
    parse_message,
    parse_message_stream,
)
from pyshiningrgb.semantic import (
    Method03Submethod,
    RenderMode,
    get_submethod,
    parse_semantic_payload,
)

__version__: str = _importlib_metadata.version(__package__ or __name__)

__all__ = [
    # Version
    "__version__",
    # Client (high-level API)
    "ShiningRGBClient",
    "ImageUploadSequence",
    # Protocol (low-level)
    "Direction",
    "parse_message",
    "parse_message_stream",
    "build_c2s_message",
    "build_s2c_message",
    "MAX_MESSAGE_SIZE",
    "MAX_C2S_PAYLOAD",
    "MAX_S2C_PAYLOAD",
    # Semantic
    "RenderMode",
    "Method03Submethod",
    "parse_semantic_payload",
    "get_submethod",
    # Builders
    "build_mode_select",
    "build_library_load",
    "build_data_transfer_first_chunk",
    "build_data_transfer_chunk",
    "build_transfer_complete",
    "build_data_transfer_auto",
    "build_method_06",
    "build_method_09",
    "build_method_0a",
]
