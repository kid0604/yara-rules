rule Windows_Trojan_Rhadamanthys_c4760266
{
	meta:
		author = "Elastic Security"
		id = "c4760266-bbff-4428-a7a5-bca7513c7993"
		fingerprint = "53a04d385ef3a59b76500effaf740cd0e7d825ea5515f871097d82899b0cfc44"
		creation_date = "2024-06-05"
		last_modified = "2024-06-12"
		threat_name = "Windows.Trojan.Rhadamanthys"
		reference_sample = "05074675b07feb8e7556c5af449f5e677e0fabfb09b135971afbb11743bf3165"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Rhadamanthys"
		filetype = "executable"

	strings:
		$a = { 55 8B EC 83 EC 14 83 7D 08 00 53 8B D8 74 50 56 57 8B 7D 0C 6A 10 2B FB 5E 56 8D 45 EC 53 50 ?? ?? ?? ?? ?? 83 C4 0C 90 8B 4D 10 8B C3 2B CB 89 75 FC 8A 14 07 32 10 88 14 01 40 FF 4D FC 75 F2 }

	condition:
		all of them
}
