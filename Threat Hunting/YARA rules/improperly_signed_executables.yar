import "pe"

rule Improperly_Signed_Executables
{
    meta:
        description = "Detects improperly signed executables"
        author = "Aaron Amran"
        date = "2024-10-25"
        version = "1.0"

    condition:
        not pe.is_signed or
        for any i in (0 .. pe.number_of_signatures) : (
        not pe.signatures[i].issuer contains "Microsoft Corporation" and
        not pe.signatures[i].verified or
        not pe.signatures[i].valid_on(1729839632)   // Current timestamp in Unix epoch format
     )        
}
