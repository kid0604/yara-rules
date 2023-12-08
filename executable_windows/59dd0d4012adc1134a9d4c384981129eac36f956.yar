import "pe"

rule MESSv120
{
	meta:
		author = "malware-lu"
		description = "Detects MESSv120 malware by checking for a specific byte sequence at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FA B9 [2] F3 [2] E3 ?? EB ?? EB ?? B6 }

	condition:
		$a0 at pe.entry_point
}
