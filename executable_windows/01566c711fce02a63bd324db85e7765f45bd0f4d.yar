import "pe"

rule BobSoftMiniDelphiBoBBobSoft
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting BobSoftMiniDelphiBoBBobSoft malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 [4] E8 [4] 33 C0 55 68 [4] 64 FF 30 64 89 20 B8 }
		$a1 = { 55 8B EC 83 C4 F0 53 B8 [4] E8 [4] 33 C0 55 68 [4] 64 FF 30 64 89 20 B8 [4] E8 }
		$a2 = { 55 8B EC 83 C4 F0 B8 [4] E8 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}
