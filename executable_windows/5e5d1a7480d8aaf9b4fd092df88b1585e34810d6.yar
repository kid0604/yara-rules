import "pe"

rule PECompactv0971v0976
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact versions 0.971 and 0.976"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }

	condition:
		$a0 at pe.entry_point
}
