import "pe"

rule EXELOCK66615
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of EXELOCK66615 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BA [2] BF [2] EB ?? EA [4] 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9 }

	condition:
		$a0 at pe.entry_point
}
