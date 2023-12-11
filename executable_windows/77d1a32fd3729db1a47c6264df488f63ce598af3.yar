rule Windows_Trojan_Generic_96cdf3c4
{
	meta:
		author = "Elastic Security"
		id = "96cdf3c4-6f40-4eb3-8bfd-b3c41422388a"
		fingerprint = "1037576e2c819031d5dc8067650c6b869e4d352ab7553fb5676a358059b37943"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "9a4d68de36f1706a3083de7eb41f839d8c7a4b8b585cc767353df12866a48c81"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic 96cdf3c4"
		filetype = "executable"

	strings:
		$a1 = { 74 24 28 48 8B 46 10 48 8B 4E 18 E8 9A CA F8 FF 84 C0 74 27 48 8B 54 }
		$a2 = { F2 74 28 48 89 54 24 18 48 89 D9 48 89 D3 E8 55 40 FF FF 84 C0 }

	condition:
		all of them
}
