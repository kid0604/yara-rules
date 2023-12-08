import "pe"
import "math"

rule HasRichSignature : PECheck
{
	meta:
		author = "_pusher_"
		description = "Rich Signature Check"
		date = "2016-07"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = "Rich" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and ( for any of ($a*) : ($ in (0x0.. uint32(0x3c))))
}
