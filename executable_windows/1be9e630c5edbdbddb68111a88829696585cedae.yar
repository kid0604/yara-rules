import "pe"

rule Aluwainv809
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B EC 1E E8 [2] 9D 5E }

	condition:
		$a0 at pe.entry_point
}
