import "pe"

rule tElockv042
{
	meta:
		author = "malware-lu"
		description = "Detects tElockv042 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

	condition:
		$a0 at pe.entry_point
}
