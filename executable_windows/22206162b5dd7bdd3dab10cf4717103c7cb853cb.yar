import "pe"

rule FSG131dulekxt
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate the presence of a certain type of malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [3] 00 BF [3] 00 BB [3] 00 53 BB [3] 00 B2 80 }

	condition:
		$a0 at pe.entry_point
}
