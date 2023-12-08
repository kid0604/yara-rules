import "pe"

rule SENDebugProtector
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of SENDebug Protector in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BB [4] 00 [5] 29 [2] 4E E8 }

	condition:
		$a0 at pe.entry_point
}
