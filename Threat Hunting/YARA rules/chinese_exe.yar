import "pe"

rule chinese_exe {
    meta:
    description = "Detects PE files with Chinese language identifiers (0x04 or 0x004)"
    author = "Aaron Amran"
    date = "2024-09-28"
    version = "1.0"

    condition:
    // Ensure the file is a PE and has Chinese language identifier
    pe.is_pe and
    (pe.language(0x04) or pe.language(0x004))
 }
