import "pe"

rule PseudoSigner01PENinja131Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate a pseudo signing technique used by malware."
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }

	condition:
		$a0 at pe.entry_point
}
