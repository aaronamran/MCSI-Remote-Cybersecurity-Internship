rule HexWildcardStrings {
    meta:
        description = "Detects patterns using hex strings and wildcards"
        author = "Aaron Amran"
	student_id = "nxCLnZGLgyOUMpnDw16rtDvYuTF2"
        date = "2024-09-25"
	version = "1.0"
    
    strings:
        $hex_string1 = { 68 ?? 65 6C 6C 6F }  // with wildcards
        $hex_string2 = { 77 6F 72 [1-4] 6C 64 } // with variable length

    condition:
        any of them
}
