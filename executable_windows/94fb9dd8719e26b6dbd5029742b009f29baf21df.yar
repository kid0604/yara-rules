rule Windows_Trojan_Sliver_c9cae357
{
	meta:
		author = "Elastic Security"
		id = "c9cae357-9270-4871-8fad-d9c43dcab644"
		fingerprint = "5366540c4a4f4a502b550f5397f3b53e3bc909cbc0cb82a2091cabb19bc135aa"
		creation_date = "2023-05-10"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Sliver"
		reference_sample = "27210d8d6e16c492c2ee61a59d39c461312f5563221ad4a0917d4e93b699418e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Sliver"
		filetype = "executable"

	strings:
		$a1 = { B1 F9 3C 0A 68 0F B4 B5 B5 B5 21 B2 38 23 29 D8 6F 83 EC 68 51 8E }

	condition:
		all of them
}
