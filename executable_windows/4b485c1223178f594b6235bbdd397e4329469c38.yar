import "pe"

rule PAKSFXArchive
{
	meta:
		author = "malware-lu"
		description = "Detects PAKSFXArchive malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 [2] A1 [2] 2E [3] 2E [5] 8C D7 8E C7 8D [2] BE [2] FC AC 3C 0D }

	condition:
		$a0 at pe.entry_point
}
