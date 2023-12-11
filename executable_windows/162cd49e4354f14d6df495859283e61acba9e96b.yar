import "pe"

rule YodasProtectorv1032Beta2AshkbizDanehkar
{
	meta:
		author = "malware-lu"
		description = "YodasProtectorv1032Beta2AshkbizDanehkar rule to detect specific code pattern at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
