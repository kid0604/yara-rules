import "pe"

rule COPv10c1988
{
	meta:
		author = "malware-lu"
		description = "Detects COPv10c1988 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF [2] BE [2] B9 [2] AC 32 [3] AA E2 ?? 8B [3] EB ?? 90 }

	condition:
		$a0 at pe.entry_point
}
