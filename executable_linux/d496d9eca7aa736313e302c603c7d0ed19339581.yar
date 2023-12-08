rule Linux_Cryptominer_Malxmr_f35a670c
{
	meta:
		author = "Elastic Security"
		id = "f35a670c-7599-4c93-b08b-463c4a93808a"
		fingerprint = "9064024118d30d89bdc093d5372a0d9fefd43eb1ac6359dbedcf3b73ba93f312"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "a73808211ba00b92f8d0027831b3aa74db15f068c53dd7f20fcadb294224f480"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { 4C 01 CD 48 0F AF D6 48 8D 54 55 00 89 DD 48 31 D7 48 C1 C7 20 }

	condition:
		all of them
}
