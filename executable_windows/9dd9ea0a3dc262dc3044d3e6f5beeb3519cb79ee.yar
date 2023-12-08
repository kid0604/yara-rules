rule Windows_Trojan_Blister_9d757838
{
	meta:
		author = "Elastic Security"
		id = "9d757838-ebaa-4ecf-b927-ac0f4848c9cb"
		fingerprint = "4ef2e22d0006b127b253d02073cde0d805d22d8696562feabc94020e287e2eb2"
		creation_date = "2022-04-26"
		last_modified = "2022-06-09"
		threat_name = "Windows.Trojan.Blister"
		reference_sample = "863de84a39c9f741d8103db83b076695d0d10a7384e4e3ba319c05a6018d9737"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Blister"
		filetype = "executable"

	strings:
		$a1 = { 65 48 8B 04 25 60 00 00 00 44 0F B7 DB 48 8B 48 ?? 48 8B 41 ?? C7 45 48 ?? ?? ?? ?? 4C 8B 40 ?? 49 63 40 ?? }
		$a2 = { B9 FF FF FF 7F 89 5D 40 8B C1 44 8D 63 ?? F0 44 01 65 40 49 2B C4 75 ?? 39 4D 40 0F 85 ?? ?? ?? ?? 65 48 8B 04 25 60 00 00 00 44 0F B7 DB }

	condition:
		any of them
}
