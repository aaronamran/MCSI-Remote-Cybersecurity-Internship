rule more_than_3_urls
{
    meta:
        description = "Detects executable files with more than 3 occurrences of URLs (http:// or https://)"
        author = "Aaron Amran"
        date = "2024-09-26"
	version = "1.0"

 strings:
     $http = "http://"
     $https = "https://"

 condition:
     // Check if file is a Portable Executable (PE) and count the number of URLs
     uint16(0) == 0x5A4D and 
     ( 
         #http >= 3 or 
         #https >= 3 or 
         (#http + #https) > 3
     )
}
