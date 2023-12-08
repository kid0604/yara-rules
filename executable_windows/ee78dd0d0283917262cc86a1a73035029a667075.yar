import "pe"
import "math"

rule IsPE64 : PECheck
{
	meta:
		description = "Check if the file is a 64-bit Portable Executable (PE) file"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint16( uint32(0x3C)+0x18)==0x020B
}
