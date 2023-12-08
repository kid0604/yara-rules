import "pe"
import "math"

rule IsConsole : PECheck
{
	meta:
		description = "Check if the file is a Windows Console executable"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint16( uint32(0x3C)+0x5C)==0x0003
}
