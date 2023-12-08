import "pe"
import "math"

rule HasTaggantSignature : PECheck
{
	meta:
		author = "_pusher_"
		description = "TaggantSignature Check"
		date = "2016-07"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 54 41 47 47 ?? ?? ?? ?? ?? ?? 00 00 ?? 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 09 30 07 06 05 2B 0E 03 02 1A 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 01 A0 82 ?? ?? 04 82 ?? ?? ?? 00 01 00 ?? ?? }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $a0
}
