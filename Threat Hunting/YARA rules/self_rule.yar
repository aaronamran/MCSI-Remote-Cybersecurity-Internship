rule Find_Self {
    /* 
    Rule Name: self_rule.yar
    */
    meta:
        description = "A rule to find the YARA rule itself"
        author = "Aaron Amran Bin Amiruddin"
        date = "2024-09-25"
        reference = "Write A YARA Rule That Can Find Itself"
    strings:
        $my_string = "I love YARA"
    condition:
        $my_string
}
