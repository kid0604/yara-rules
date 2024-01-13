rule Windows_Generic_Threat_97c1a260
{
	meta:
		author = "Elastic Security"
		id = "97c1a260-9b43-458e-a9ac-2391aee1bcb8"
		fingerprint = "9cd93a8def2d2fac61a5b37d82b97c18ce8bf3410aa6ec7531ec28378f5c98cc"
		creation_date = "2024-01-07"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "2cc85ebb1ef07948b1ddf1a793809b76ee61d78c07b8bf6e702c9b17346a20f1"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 53 56 57 E8 14 31 00 00 8B F0 85 F6 0F 84 39 01 00 00 8B 16 33 DB 8B CA 8D 82 90 00 00 00 3B D0 74 0E 8B 7D 08 39 39 74 09 83 C1 0C 3B C8 75 F5 8B CB 85 C9 0F 84 11 01 00 00 8B 79 }

	condition:
		all of them
}
