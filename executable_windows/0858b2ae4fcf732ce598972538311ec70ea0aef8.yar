import "pe"

rule PECrypt32v102
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PECrypt32v102 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 5B 83 [2] EB ?? 52 4E 44 21 }

	condition:
		$a0 at pe.entry_point
}
