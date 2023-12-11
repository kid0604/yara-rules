import "pe"
import "math"

rule IsPE32 : PECheck
{
	meta:
		description = "Checks if the file is a PE32 executable"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint16( uint32(0x3C)+0x18)==0x010B
}
