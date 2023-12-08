import "pe"

rule tElockv060
{
	meta:
		author = "malware-lu"
		description = "Detects tElockv060 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }

	condition:
		$a0 at pe.entry_point
}
