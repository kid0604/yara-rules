import "pe"

rule HACKSTOPv118
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 52 BA [2] 5A EB ?? 9A [4] 30 CD 21 [3] FD 02 [2] CD 20 0E 1F 52 BA [2] 5A EB }

	condition:
		$a0 at pe.entry_point
}
