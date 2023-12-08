import "pe"

rule tElockv085f
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElockv085f malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }

	condition:
		$a0 at pe.entry_point
}
