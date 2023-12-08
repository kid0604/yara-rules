import "pe"

rule WARNINGTROJANADinjector
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of WARNINGTROJANADinjector malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 61 BE 00 20 44 00 8D BE 00 F0 FB FF C7 87 9C E0 04 00 6A F0 8A 5E 57 83 CD FF EB 0E }

	condition:
		$a0 at pe.entry_point
}
