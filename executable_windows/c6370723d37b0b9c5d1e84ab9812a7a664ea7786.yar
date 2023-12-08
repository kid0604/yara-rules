import "pe"

rule Packmanv0001
{
	meta:
		author = "malware-lu"
		description = "Detects Packmanv0001 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 [2] FF FF 8D 98 [3] FF 8D [2] 01 00 00 [28] 00 00 }

	condition:
		$a0 at pe.entry_point
}
