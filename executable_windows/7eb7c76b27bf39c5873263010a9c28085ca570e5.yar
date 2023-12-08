import "pe"

rule StonesPEEncruptorv113
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Stones PE Encryptor v1.13"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 [4] 5D 8B D5 81 }

	condition:
		$a0 at pe.entry_point
}
