import "pe"

rule SimplePack10Xbagie
{
	meta:
		author = "malware-lu"
		description = "Detects the SimplePack10Xbagie malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 [2] 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 }

	condition:
		$a0 at pe.entry_point
}
