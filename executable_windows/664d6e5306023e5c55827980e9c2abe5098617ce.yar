import "math"
import "pe"

rule IsDLL : PECheck
{
	meta:
		description = "Check if the file is a DLL"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and ( uint16( uint32(0x3C)+0x16)&0x2000)==0x2000
}
