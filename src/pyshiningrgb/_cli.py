"""CLI application for controlling ShiningRGB LED masks.

This module provides a command-line interface for sending images, videos, or random
noise to ShiningRGB LED masks over WiFi.
"""

from __future__ import annotations

import argparse
import random
import socket
import subprocess
import sys
import time
from typing import TYPE_CHECKING, cast

from PIL import Image

from pyshiningrgb.client import ShiningRGBClient
from pyshiningrgb.protocol import parse_message
from pyshiningrgb.semantic import AnimationType

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

# Display dimensions
MASK_WIDTH = 0x3A  # 58 pixels
MASK_HEIGHT = 0x50  # 80 pixels


def convert_rgb_to_rgb565(rgb_data: bytes, width: int, height: int) -> bytes:
    """Convert raw RGB data to RGB565 format.

    Args:
        rgb_data: Raw RGB bytes (3 bytes per pixel)
        width: Image width in pixels
        height: Image height in pixels

    Returns:
        Bytes containing RGB565 pixel data (2 bytes per pixel)
    """
    # Pre-allocate output buffer for better performance
    num_pixels = len(rgb_data) // 3
    pixel_data = bytearray(num_pixels * 2)

    # Process pixels in bulk for better performance
    for i in range(num_pixels):
        rgb_offset = i * 3
        r = rgb_data[rgb_offset]
        g = rgb_data[rgb_offset + 1]
        b = rgb_data[rgb_offset + 2]

        # RGB565: RRRRR GGGGGG BBBBB
        pixel = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)

        # Write as little-endian
        out_offset = i * 2
        pixel_data[out_offset] = pixel & 0xFF
        pixel_data[out_offset + 1] = (pixel >> 8) & 0xFF

    return bytes(pixel_data)


class VideoFrameReader:
    """Read frames from a video file using ffmpeg subprocess."""

    def __init__(self, video_path: str, width: int, height: int) -> None:
        """Initialize video reader.

        Args:
            video_path: Path to video file
            width: Target width in pixels
            height: Target height in pixels
        """
        self.video_path = video_path
        self.width = width
        self.height = height
        self.frame_size = width * height * 3  # RGB24 format
        self.process: subprocess.Popen[bytes] | None = None
        self.source_fps: float | None = None

        # Get video FPS first
        self._get_video_info()

    def _get_video_info(self) -> None:
        """Get video information using ffprobe.

        Raises:
            ValueError: If video info cannot be determined
        """
        try:
            cmd = [
                "ffprobe",
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=r_frame_rate",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                self.video_path,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            fps_str = result.stdout.strip()

            if not fps_str:
                raise ValueError("No video stream found in file - is this a video file?")

            # Parse fraction like "30/1" or "30000/1001"
            if "/" in fps_str:
                num, den = fps_str.split("/")
                if not num or not den:
                    raise ValueError(f"Invalid frame rate format: {fps_str}")
                self.source_fps = float(num) / float(den)
            else:
                self.source_fps = float(fps_str)

            if self.source_fps <= 0:
                raise ValueError(f"Invalid FPS value: {self.source_fps}")

        except subprocess.CalledProcessError as e:
            print(f"[!] Error: ffprobe failed: {e}")
            print("[!] Make sure ffmpeg/ffprobe is installed and the file is a valid video")
            raise
        except ValueError as e:
            print(f"[!] Error: {e}")
            raise
        except Exception as e:
            print(f"[!] Error: Could not determine video FPS: {e}")
            raise

    def start(self) -> None:
        """Start the ffmpeg subprocess."""
        # Limit output FPS to 5 to avoid decoding tons of frames we'll drop
        cmd = [
            "ffmpeg",
            "-i",
            self.video_path,
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "-s",
            f"{self.width}x{self.height}",
            "-r",
            "5",  # Limit to 5 fps output
            "-",  # Output to stdout
        ]

        self.process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=self.frame_size
        )

    def read_frame_raw(self) -> bytes | None:
        """Read one frame from the video as raw RGB24 data.

        Returns:
            RGB24 pixel data bytes, or None if end of video
        """
        if not self.process or not self.process.stdout:
            return None

        rgb_data = self.process.stdout.read(self.frame_size)

        if len(rgb_data) != self.frame_size:
            # End of video or error
            return None

        return rgb_data

    def read_frame(self) -> bytes | None:
        """Read one frame from the video and convert to RGB565.

        Returns:
            RGB565 pixel data bytes, or None if end of video
        """
        rgb_data = self.read_frame_raw()
        if rgb_data is None:
            return None

        # Convert RGB24 to RGB565
        return convert_rgb_to_rgb565(rgb_data, self.width, self.height)

    def close(self) -> None:
        """Close the ffmpeg subprocess."""
        if self.process:
            self.process.kill()
            self.process.wait()
            self.process = None


def generate_random_pixel_data(width: int, height: int) -> bytes:
    """Generate random RGB565 pixel data.

    Args:
        width: Image width in pixels
        height: Image height in pixels

    Returns:
        Bytes containing random pixel data (2 bytes per pixel)
    """
    pixel_data = bytearray()
    num_pixels = width * height

    for _ in range(num_pixels):
        # Generate random 2 bytes for each pixel
        pixel_data.extend(random.randbytes(2))

    return bytes(pixel_data)


def load_and_convert_image(
    image_path: str, width: int, height: int, column_shift: int = 0
) -> bytes:
    """Load an image, resize it to fit dimensions, and convert to RGB565 format.

    The image is resized to fit within the target dimensions while preserving aspect
    ratio, then center-cropped to the exact size.

    Args:
        image_path: Path to image file
        width: Target width in pixels
        height: Target height in pixels
        column_shift: Number of columns to shift left (wrap around)

    Returns:
        Bytes containing RGB565 pixel data (2 bytes per pixel)
    """
    # Load image
    img_raw = Image.open(image_path)

    # Convert to RGB if needed
    img: PILImage
    if img_raw.mode != "RGB":
        img = img_raw.convert("RGB")
    else:
        img = img_raw

    # Calculate aspect ratios
    target_aspect = width / height
    img_aspect = img.width / img.height

    # Resize to fit with aspect ratio preservation, then crop to exact size
    if img_aspect > target_aspect:
        # Image is wider - fit by height
        new_height = height
        new_width = int(height * img_aspect)
    else:
        # Image is taller - fit by width
        new_width = width
        new_height = int(width / img_aspect)

    img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)

    # Center crop to exact dimensions
    left = (new_width - width) // 2
    top = (new_height - height) // 2
    img = img.crop((left, top, left + width, top + height))

    # Convert to pixel data - RGB565 format
    pixel_data = bytearray()
    pixels = img.load()
    assert pixels is not None, "Failed to load image pixels"

    for y in range(height):
        for x in range(width):
            # Apply column shift (wrap around)
            shifted_x = (x + column_shift) % width
            r, g, b = cast(tuple[int, int, int], pixels[shifted_x, y])
            # RGB565: RRRRR GGGGGG BBBBB
            pixel = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            pixel_data.extend(pixel.to_bytes(2, byteorder="little"))

    return bytes(pixel_data)


def read_response(sock: socket.socket, timeout: float = 1.0) -> bytes | None:
    """Read a single RPC response from socket.

    Args:
        sock: Connected socket
        timeout: Read timeout in seconds

    Returns:
        Response bytes or None if timeout
    """
    sock.settimeout(timeout)
    buffer = b""

    try:
        # Read until we have enough for magic + minimum header
        while len(buffer) < 7:
            chunk = sock.recv(1)
            if not chunk:
                return None
            buffer += chunk

            # Check if we have magic bytes at the start
            if len(buffer) >= 2 and buffer[:2] != b"\x5a\xa5":
                # Not magic, keep looking
                buffer = buffer[1:]

        # We have at least 7 bytes starting with magic
        # S2C format: magic(2) + method(1) + unknown(1) + length(2) + payload(length) + checksum(1)
        if buffer[0:2] == b"\x5a\xa5":
            # Extract length field (bytes 4-5 for S2C)
            payload_len = buffer[4] | (buffer[5] << 8)
            total_len = 7 + payload_len

            # Read remaining bytes
            while len(buffer) < total_len:
                needed = total_len - len(buffer)
                chunk = sock.recv(needed)
                if not chunk:
                    return None
                buffer += chunk

            return buffer

    except socket.timeout:
        if len(buffer) > 0:
            return buffer
        return None

    return None


def parse_rgb565_color(color_str: str) -> bytes:
    """Parse a color string to RGB565 bytes.

    Accepts formats:
        - Hex: "0x1234" or "1234" (raw RGB565 value)
        - RGB: "r,g,b" where each is 0-255

    Args:
        color_str: Color string to parse

    Returns:
        2 bytes in RGB565 format, little-endian

    Raises:
        ValueError: If format is invalid
    """
    color_str = color_str.strip()

    # Try RGB format first (r,g,b)
    if "," in color_str:
        parts = color_str.split(",")
        if len(parts) != 3:
            raise ValueError(f"RGB format requires 3 components, got {len(parts)}")
        r, g, b = (int(p.strip()) for p in parts)
        if not (0 <= r <= 255 and 0 <= g <= 255 and 0 <= b <= 255):
            raise ValueError("RGB values must be 0-255")
        # Convert to RGB565
        pixel = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        return pixel.to_bytes(2, byteorder="little")

    # Try hex format
    if color_str.startswith("0x") or color_str.startswith("0X"):
        color_str = color_str[2:]
    value = int(color_str, 16)
    if not 0 <= value <= 0xFFFF:
        raise ValueError("Hex color must be 0x0000-0xFFFF")
    return value.to_bytes(2, byteorder="little")


def send_messages(
    host: str,
    port: int,
    timeout: float = 1.0,
    loop: bool = False,
    loop_delay: float = 0.1,
    verbose: bool = False,
    image_path: str | None = None,
    column_shift: int = 0,
    video_path: str | None = None,
    animation_type: AnimationType = AnimationType.NONE,
    background_color: bytes = b"\x00\x00",
    animation_speed: int = 0,
) -> int:
    """Send RPC messages to server and print responses.

    Args:
        host: Target host
        port: Target port
        timeout: Response read timeout
        loop: If True, continuously send images
        loop_delay: Delay between loop iterations in seconds
        verbose: Show full hex dumps
        image_path: Optional path to image file
        column_shift: Number of columns to shift left (wrap around)
        video_path: Optional path to video file
        animation_type: Animation type for display
        background_color: Background color in RGB565 format (2 bytes)
        animation_speed: Animation speed from 0 (slowest) to 10 (fastest)

    Returns:
        Exit code (0 for success)
    """
    print(f"[*] Connecting to {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Initialize video reader if video mode
    video_reader: VideoFrameReader | None = None
    if video_path:
        print(f"[*] Loading video: {video_path}")
        video_reader = VideoFrameReader(video_path, MASK_WIDTH, MASK_HEIGHT)
        print(f"[*] Source video FPS: {video_reader.source_fps:.2f}")
        print("[*] Video mode: ffmpeg will downsample to ~5 FPS, display as fast as possible")

    # Load image once if provided
    if image_path:
        print(f"[*] Loading image: {image_path}")
        if column_shift:
            print(f"[*] Column shift: {column_shift}")

    try:
        sock.connect((host, port))
        print("[*] Connected successfully")
        print("=" * 80)

        # Start video reader if in video mode
        if video_reader:
            video_reader.start()

        # Initialize client
        client = ShiningRGBClient()

        # Upload loop
        upload_count = 0
        fps_history: list[float] = []  # Keep last 10 measurements for smoothing
        video_start_time = time.perf_counter() if video_reader else None
        video_frames_displayed = 0

        while True:
            loop_start = time.perf_counter()
            upload_count += 1

            # Generate pixel data
            pixel_data: bytes | None = None
            generation_time = 0.0

            if video_reader:
                # Video mode: read next frame from ffmpeg
                raw_frame = video_reader.read_frame_raw()

                if raw_frame is None:
                    # End of video
                    print("\n[*] End of video reached")
                    print(f"[*] Frames displayed: {video_frames_displayed}")
                    if video_start_time is not None:
                        elapsed_total = time.perf_counter() - video_start_time
                        avg_display_fps = (
                            video_frames_displayed / elapsed_total if elapsed_total > 0 else 0
                        )
                        print(f"[*] Average display FPS: {avg_display_fps:.2f}")
                    return 0

                # Convert the frame
                start_time = time.perf_counter()
                pixel_data = convert_rgb_to_rgb565(
                    raw_frame, video_reader.width, video_reader.height
                )
                generation_time = time.perf_counter() - start_time
                video_frames_displayed += 1

                print(f"\n[Frame #{video_frames_displayed}]")

            elif image_path:
                # Image mode
                start_time = time.perf_counter()
                pixel_data = load_and_convert_image(
                    image_path, MASK_WIDTH, MASK_HEIGHT, column_shift=column_shift
                )
                generation_time = time.perf_counter() - start_time
                print(f"\n[Upload #{upload_count}]")

            else:
                # Random mode
                start_time = time.perf_counter()
                pixel_data = generate_random_pixel_data(MASK_WIDTH, MASK_HEIGHT)
                generation_time = time.perf_counter() - start_time
                print(f"\n[Upload #{upload_count}]")

            # Prepare upload sequence
            upload_sequence = client.prepare_image_upload(
                MASK_WIDTH,
                MASK_HEIGHT,
                pixel_data,
                animation_type=animation_type,
                background_color=background_color,
                animation_speed=animation_speed,
            )

            # Send all messages
            for i, (description, msg) in enumerate(upload_sequence):
                if verbose:
                    print(f"  [{i}] {description}: {len(msg)} bytes")
                sock.send(msg)

                # Read response
                response = read_response(sock, timeout=timeout)
                if response and verbose:
                    try:
                        direction, parsed = parse_message(response)
                        print(f"      Response: method=0x{parsed.method:02x}")
                    except Exception:
                        pass

            loop_elapsed = time.perf_counter() - loop_start

            print(f"  Sent {len(upload_sequence)} messages")
            if generation_time > 0:
                print(f"  Frame processing: {generation_time * 1000:.2f} ms")
            print(f"  Total loop time: {loop_elapsed * 1000:.2f} ms")

            # Calculate FPS
            fps = 1.0 / loop_elapsed if loop_elapsed > 0 else 0
            fps_history.append(fps)
            if len(fps_history) > 10:
                fps_history.pop(0)
            avg_fps = sum(fps_history) / len(fps_history)

            print(f"  Display FPS: {fps:.2f}")
            if len(fps_history) > 1:
                print(f"  Average FPS (last {len(fps_history)}): {avg_fps:.2f}")

            if not loop and not video_reader:
                break

            if loop_delay > 0 and not video_reader:
                time.sleep(loop_delay)

        return 0

    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
        if video_reader:
            print(f"[*] Frames displayed: {video_frames_displayed}")
            if video_start_time is not None:
                elapsed_total = time.perf_counter() - video_start_time
                avg_display_fps = (
                    video_frames_displayed / elapsed_total if elapsed_total > 0 else 0
                )
                print(f"[*] Average display FPS: {avg_display_fps:.2f}")
        return 0

    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        import traceback

        traceback.print_exc()
        return 1

    finally:
        if video_reader:
            video_reader.close()
        sock.close()
        print("\n[*] Connection closed")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Send images, videos, or random noise to ShiningRGB LED mask",
        epilog="Use --video to send a video file with frame pacing. "
        "Use --image for static images. Use --loop to continuously send random frames.",
    )
    parser.add_argument(
        "--host",
        default="192.168.4.1",
        help="Target server IP (default: 192.168.4.1)",
    )
    parser.add_argument("--port", type=int, default=8810, help="Target port (default: 8810)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Response timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Continuously send images (ignored in video mode)",
    )
    parser.add_argument(
        "--loop-delay",
        type=float,
        default=0.1,
        help="Delay between uploads in seconds (default: 0.1)",
    )
    parser.add_argument("--image", type=str, help="Path to image file (e.g., bliss.jpg)")
    parser.add_argument(
        "--video",
        type=str,
        help="Path to video file (e.g., video.mp4) - enables video mode with frame pacing",
    )
    parser.add_argument(
        "--column-shift",
        type=int,
        default=0,
        help="Shift columns left by N pixels (wraps around, default: 0)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed message info")
    parser.add_argument(
        "--animation-type",
        type=str,
        choices=[e.name for e in AnimationType],
        default=AnimationType.NONE.name,
        help="Animation type (default: NONE)",
    )
    parser.add_argument(
        "--animation-speed",
        type=int,
        default=0,
        choices=range(0, 11),
        metavar="0-10",
        help="Animation speed: 0 (slowest, default) to 10 (fastest)",
    )
    parser.add_argument(
        "--background-color",
        type=str,
        default="0x0000",
        help="Background color as RGB565 hex (e.g., 0xf800 for red) or RGB (e.g., 255,0,0)",
    )
    args = parser.parse_args()

    # Validate mutually exclusive options
    if args.video and args.image:
        print("[!] Error: --video and --image cannot be used together", file=sys.stderr)
        sys.exit(1)

    try:
        background_color = parse_rgb565_color(args.background_color)
    except ValueError as e:
        print(f"[!] Error: Invalid background color: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        exit_code = send_messages(
            args.host,
            args.port,
            timeout=args.timeout,
            loop=args.loop,
            loop_delay=args.loop_delay,
            verbose=args.verbose,
            image_path=args.image,
            column_shift=args.column_shift,
            video_path=args.video,
            animation_type=AnimationType[args.animation_type],
            background_color=background_color,
            animation_speed=args.animation_speed,
        )
        sys.exit(exit_code)
    except Exception as e:
        print(f"\n[!] FATAL ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(2)
