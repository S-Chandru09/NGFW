import hashlib
import struct
from pathlib import Path
from typing import Optional

from models.packet_upload import PacketValidationResult, PcapFileType

PCAP_MAGIC_NUMBERS = {
  0xA1B2C3D4,
  0xD4C3B2A1,
  0xA1B23C4D,
  0x4D3CB2A1,
}
PCAPNG_MAGIC_NUMBER = 0x0A0D0D0A
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


class PacketValidator:
  def __init__(self, max_file_size_mb: int = 100) -> None:
    self.max_file_size_bytes = max_file_size_mb * 1024 * 1024

  def validate_filename(self, filename: str) -> tuple[bool, list[str]]:
    errors: list[str] = []

    if not filename:
      errors.append("Filename is required")
      return False, errors

    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
      errors.append(f"Invalid file extension '{extension}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    return len(errors) == 0, errors

  def validate_file_size(self, file_size: int) -> tuple[bool, list[str]]:
    errors: list[str] = []

    if file_size <= 0:
      errors.append("Uploaded file is empty")

    if file_size > self.max_file_size_bytes:
      max_mb = self.max_file_size_bytes / (1024 * 1024)
      errors.append(f"File size exceeds maximum allowed size of {max_mb:.0f} MB")

    return len(errors) == 0, errors

  def detect_pcap_type(self, file_header: bytes) -> PcapFileType:
    if len(file_header) < 4:
      return PcapFileType.UNKNOWN

    magic_number = struct.unpack("I", file_header[:4])[0]

    if magic_number in PCAP_MAGIC_NUMBERS:
      return PcapFileType.PCAP

    if magic_number == PCAPNG_MAGIC_NUMBER:
      return PcapFileType.PCAPNG

    return PcapFileType.UNKNOWN

  def validate_magic_bytes(self, file_header: bytes) -> tuple[bool, PcapFileType, list[str]]:
    errors: list[str] = []
    file_type = self.detect_pcap_type(file_header)

    if file_type == PcapFileType.UNKNOWN:
      errors.append("Invalid PCAP file format. File header does not match PCAP or PCAPNG magic numbers")

    return file_type != PcapFileType.UNKNOWN, file_type, errors

  def calculate_file_hash(self, file_content: bytes) -> str:
    return hashlib.sha256(file_content).hexdigest()

  def count_packets(self, file_path: Path, file_type: PcapFileType) -> tuple[int, list[str]]:
    warnings: list[str] = []
    packet_count = 0

    try:
      if file_type == PcapFileType.PCAP:
        from scapy.utils import PcapReader

        with PcapReader(str(file_path)) as reader:
          for _ in reader:
            packet_count += 1

      elif file_type == PcapFileType.PCAPNG:
        from scapy.utils import PcapNgReader

        with PcapNgReader(str(file_path)) as reader:
          for _ in reader:
            packet_count += 1

    except ImportError:
      warnings.append("Scapy is not available. Packet count validation skipped")
      return 0, warnings
    except Exception as exc:
      warnings.append(f"Could not count packets using Scapy: {exc}")
      return 0, warnings

    return packet_count, warnings

  def validate_pcap_file(
    self,
    filename: str,
    file_content: bytes,
    file_path: Optional[Path] = None,
  ) -> PacketValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    filename_valid, filename_errors = self.validate_filename(filename)
    errors.extend(filename_errors)

    file_size = len(file_content)
    size_valid, size_errors = self.validate_file_size(file_size)
    errors.extend(size_errors)

    file_header = file_content[:24] if len(file_content) >= 24 else file_content
    magic_valid, file_type, magic_errors = self.validate_magic_bytes(file_header)
    errors.extend(magic_errors)

    file_hash = self.calculate_file_hash(file_content)
    packet_count = 0

    if magic_valid and file_path is not None and file_path.exists():
      packet_count, packet_warnings = self.count_packets(file_path, file_type)
      warnings.extend(packet_warnings)

      if packet_count == 0 and not packet_warnings:
        errors.append("PCAP file contains no packets")

    if file_path is not None:
      is_valid = filename_valid and size_valid and magic_valid and packet_count > 0
    else:
      is_valid = filename_valid and size_valid and magic_valid

    if magic_valid and packet_count == 0 and file_path is not None and not errors:
      warnings.append("Packet count could not be verified")

    return PacketValidationResult(
      is_valid=is_valid,
      file_type=file_type,
      packet_count=packet_count,
      file_size=file_size,
      file_hash=file_hash,
      errors=errors,
      warnings=warnings,
    )
