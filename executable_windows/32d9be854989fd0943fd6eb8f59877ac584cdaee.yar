rule Windows_Generic_Threat_3f060b9c
{
	meta:
		author = "Elastic Security"
		id = "3f060b9c-8c35-4f0f-9dfd-10be6355bea9"
		fingerprint = "5bc1d19faa8fc07ef669f6f63baceee5fe452c0e2d54d6154bcc01e11606ae6f"
		creation_date = "2024-01-10"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "32e7a40b13ddbf9fc73bd12c234336b1ae11e2f39476de99ebacd7bbfd22fba0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 51 53 56 8B F1 E8 4B BE FF FF 8D 45 FC 8B CE 50 FF 75 10 FF 75 0C E8 69 FE FF FF 8B D8 8B CE 53 E8 4B FD FF FF 85 C0 0F 84 C6 00 00 00 8B 46 40 83 F8 02 0F 84 B3 00 00 00 83 F8 05 }

	condition:
		all of them
}
