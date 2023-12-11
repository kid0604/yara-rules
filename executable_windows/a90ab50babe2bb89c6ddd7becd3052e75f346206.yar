import "pe"

rule CopyProtectorv20
{
	meta:
		author = "malware-lu"
		description = "Detects CopyProtectorv20 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2E A2 [2] 53 51 52 1E 06 B4 ?? 1E 0E 1F BA [2] CD 21 1F }

	condition:
		$a0 at pe.entry_point
}
