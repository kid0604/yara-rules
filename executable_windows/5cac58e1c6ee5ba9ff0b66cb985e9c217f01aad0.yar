import "pe"

rule NullsoftPIMPInstallSystemv13x
{
	meta:
		author = "malware-lu"
		description = "Detects the Nullsoft PIMP Install System v1.3x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC [2] 00 00 56 57 6A ?? BE [4] 59 8D BD }

	condition:
		$a0 at pe.entry_point
}
