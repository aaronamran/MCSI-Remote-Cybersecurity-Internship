import "pe"

rule small_pe {
    meta:
        description = "Detects small Portable Executable files under 500KB"
        author = "Aaron Amran Bin Amiruddin"
	student_id = "nxCLnZGLgyOUMpnDw16rtDvYuTF2"
        date_created = "2024-09-25"
	version = "1.0"
    
    condition:
        // File size is less than 500KB(500 * 1024 bytes = 512000 bytes)
        filesize < 512000 and
        
        // File type is Portable Executable (PE)
        pe.is_pe
}
