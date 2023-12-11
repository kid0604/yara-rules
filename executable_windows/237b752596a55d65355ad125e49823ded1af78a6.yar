import "pe"

rule SkDUndetectablerPro20NoUPXMethodSkD
{
	meta:
		author = "malware-lu"
		description = "Detects SkDUndetectablerPro20NoUPXMethodSkD malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40 }

	condition:
		$a0 at pe.entry_point
}
