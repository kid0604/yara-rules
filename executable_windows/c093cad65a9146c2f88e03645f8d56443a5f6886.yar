import "pe"

rule Packman0001bubba
{
	meta:
		author = "malware-lu"
		description = "Detects Packman0001bubba malware based on its entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 [3] FF 8D [2] 01 00 00 }

	condition:
		$a0 at pe.entry_point
}
