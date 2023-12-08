import "math"
import "pe"

rule IsGoLink
{
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "www.GoDevTool.com"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 47 6F 4C 69 6E 6B }

	condition:
		uint16(0)==0x5A4D and $a0 at 0x40
}
