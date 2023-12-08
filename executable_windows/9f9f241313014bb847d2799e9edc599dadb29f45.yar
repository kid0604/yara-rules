import "pe"

rule tElockv041x
{
	meta:
		author = "malware-lu"
		description = "Detects tElockv041x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 [2] 59 EB 01 EB AC 54 E8 03 [3] 5C EB 08 }

	condition:
		$a0 at pe.entry_point
}
