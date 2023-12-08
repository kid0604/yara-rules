import "pe"

rule Freshbindv20gFresh
{
	meta:
		author = "malware-lu"
		description = "Detects Freshbindv20gFresh malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00 }

	condition:
		$a0 at pe.entry_point
}
