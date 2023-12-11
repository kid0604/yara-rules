import "pe"

rule ShegerdDongleV478MSCo
{
	meta:
		author = "malware-lu"
		description = "Detects ShegerdDongle version 478 MS Co malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 32 00 00 00 B8 [4] 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C }

	condition:
		$a0 at pe.entry_point
}
