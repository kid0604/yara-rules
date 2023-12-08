import "pe"

rule WARNINGTROJANRobinPE
{
	meta:
		author = "malware-lu"
		description = "Detects the WARNINGTROJANRobinPE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
