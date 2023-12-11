import "pe"
import "math"

rule IsPacked : PECheck
{
	meta:
		description = "Entropy Check"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and math.entropy(0, filesize )>=7.0
}
