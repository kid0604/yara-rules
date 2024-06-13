rule Windows_Trojan_DustyWarehouse_3fef514b
{
	meta:
		author = "Elastic Security"
		id = "3fef514b-9499-47ce-bf84-8393f8d0260f"
		fingerprint = "077bc59b4b6298e405c1cd37d9416667371190e5d8c83a9a9502753c9065df58"
		creation_date = "2024-05-30"
		last_modified = "2024-06-12"
		threat_name = "Windows.Trojan.DustyWarehouse"
		reference_sample = "4ad024f53595fdd380f5b5950b62595cd47ac424d2427c176a7b2dfe4e1f35f7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan DustyWarehouse"
		filetype = "executable"

	strings:
		$a = { 48 83 EC 30 48 C7 44 24 20 FE FF FF FF 48 89 5C 24 48 48 89 74 24 50 C7 44 24 40 [4] 48 8B 39 48 8B 71 08 48 8B 59 10 48 8B 49 18 ?? ?? ?? ?? ?? ?? 84 DB 74 05 E8 E1 01 00 00 48 8B CE }

	condition:
		all of them
}
