import "pe"
import "math"

rule IsSuspicious
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "Might be PE Virus"
		os = "windows"
		filetype = "executable"

	condition:
		uint32(0x20)==0x20202020
}
