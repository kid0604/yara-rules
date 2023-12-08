import "math"
import "pe"

rule IsWindowsGUI : PECheck
{
	meta:
		description = "Checks if the file is a Windows GUI executable"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint16( uint32(0x3C)+0x5C)==0x0002
}
