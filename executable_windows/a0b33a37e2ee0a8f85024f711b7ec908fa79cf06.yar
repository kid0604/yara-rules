import "pe"

rule NullsoftPIMPInstallSystemv1x
{
	meta:
		author = "malware-lu"
		description = "Detects the Nullsoft PIMP Install System v1.x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 5C 53 55 56 57 FF 15 [3] 00 }

	condition:
		$a0 at pe.entry_point
}
