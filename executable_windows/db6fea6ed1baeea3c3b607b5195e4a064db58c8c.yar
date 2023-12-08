import "pe"

rule Petitev211
{
	meta:
		author = "malware-lu"
		description = "Detects Petitev211 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 68 [4] 64 [6] 64 [6] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}
