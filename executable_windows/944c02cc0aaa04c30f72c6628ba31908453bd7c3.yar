import "pe"

rule tElockv080
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElockv080 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 F9 11 00 00 C3 83 }

	condition:
		$a0 at pe.entry_point
}
