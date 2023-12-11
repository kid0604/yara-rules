import "pe"

rule HACKSTOPv100
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FA BD [2] FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F }

	condition:
		$a0 at pe.entry_point
}
