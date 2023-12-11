import "pe"

rule PKLITEv112v115v1201
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PKLITE v1.12, v1.15, or v1.20.1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B 06 [2] 73 ?? 2D [2] FA 8E D0 FB 2D [2] 8E C0 50 B9 [2] 33 FF 57 BE [2] FC F3 A5 CB B4 09 BA [2] CD 21 CD 20 }

	condition:
		$a0 at pe.entry_point
}
