import "pe"

rule Upack_PatchoranyVersionDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Upack PatchoranyVersionDwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 09 00 00 00 [3] 00 E9 06 02 }

	condition:
		$a0 at pe.entry_point
}
