import "pe"

rule BJFntv13
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB ?? 3A [2] 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }

	condition:
		$a0 at pe.entry_point
}
