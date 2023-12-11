import "pe"

rule SuckStopv111
{
	meta:
		author = "malware-lu"
		description = "Detects the SuckStopv111 malware based on the entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB [3] BE [2] B4 30 CD 21 EB ?? 9B }

	condition:
		$a0 at pe.entry_point
}
