rule ATM_HelloWorld : malware
{
	meta:
		description = "Search strings and procedure in HelloWorld ATM Malware"
		author = "xylitol@temari.fr"
		date = "2019-01-13"
		os = "windows"
		filetype = "executable"

	strings:
		$api1 = "CscCngOpen" ascii wide
		$api2 = "CscCngClose" ascii wide
		$string1 = "%d,%02d;" ascii wide
		$string2 = "MAX_NOTES" ascii wide
		$hex_var1 = { FF 15 ?? ?? ?? ?? BF 00 80 00 00 85 C7 }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
