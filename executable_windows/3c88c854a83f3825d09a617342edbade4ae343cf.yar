import "pe"

rule tElockv071
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElockv071 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 ED 10 00 00 C3 83 }

	condition:
		$a0 at pe.entry_point
}
