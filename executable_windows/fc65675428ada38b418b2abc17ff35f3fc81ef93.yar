import "pe"

rule VideoLanClient
{
	meta:
		author = "malware-lu"
		description = "Detects VideoLanClient malware based on entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 83 EC 08 [15] FF FF }

	condition:
		$a0 at pe.entry_point
}
