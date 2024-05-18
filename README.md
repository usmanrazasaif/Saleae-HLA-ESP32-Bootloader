# Saleae-HLA-ESP32-Bootloader
Developed a High-Level Analyzer (HLA) for the ESP32 ROM bootloader's UART protocol, tailored for use with Saleae Logic Analyzers.

The bootloader protocol, utilizing SLIP packet framing, requires precise handling of data transmissions, including special encoding schemes for packet integrity. We devised an HLA that identifies and decodes SLIP packets, reconstructs escaped bytes, and extracts essential packet information like command identifiers and payload data. This HLA aids in debugging and analyzing the bootloader's communication, providing insights into commands and responses.
