import "pe"

rule tElockv070
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElockv070 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }

	condition:
		$a0 at pe.entry_point
}
