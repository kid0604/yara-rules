import "pe"

rule piritv15
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of piritv15 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5B 24 55 50 44 FB 32 2E 31 5D }

	condition:
		$a0 at pe.entry_point
}
