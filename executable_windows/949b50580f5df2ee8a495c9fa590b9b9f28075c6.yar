import "pe"

rule PureBasic4xNeilHodgson
{
	meta:
		author = "malware-lu"
		description = "Detects PureBasic 4.x compiled files by Neil Hodgson"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [2] 00 00 68 00 00 00 00 68 [3] 00 E8 [3] 00 83 C4 0C 68 00 00 00 00 E8 [3] 00 A3 [3] 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 [3] 00 A3 }

	condition:
		$a0 at pe.entry_point
}
