import "pe"

rule PECryptv100v101
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PECrypt version 1.00 and 1.01"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

	condition:
		$a0 at pe.entry_point
}
