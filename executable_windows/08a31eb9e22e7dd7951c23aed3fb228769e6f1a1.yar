import "pe"

rule VxExplosion1000
{
	meta:
		author = "malware-lu"
		description = "Detects VxExplosion1000 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 1E 06 50 81 [3] 56 FC B8 21 35 CD 21 2E [4] 2E [4] 26 [6] 74 ?? 8C D8 48 8E D8 }

	condition:
		$a0 at pe.entry_point
}
