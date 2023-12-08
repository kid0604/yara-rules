rule Windows_Trojan_Emotet_db7d33fa
{
	meta:
		author = "Elastic Security"
		id = "db7d33fa-e50c-4c59-ab92-edb74aac87c9"
		fingerprint = "eac196154ab1ad636654c966e860dcd5763c50d7b8221dbbc7769c879daf02fd"
		creation_date = "2022-05-09"
		last_modified = "2022-06-09"
		threat_name = "Windows.Trojan.Emotet"
		reference_sample = "08c23400ff546db41f9ddbbb19fa75519826744dde3b3afb38f3985266577afc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Emotet based on specific byte patterns"
		filetype = "executable"

	strings:
		$chunk_0 = { 4C 8D 9C 24 ?? ?? ?? ?? 8B C3 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 5D C3 }
		$chunk_1 = { 8B C7 41 0F B7 4C 45 ?? 41 8B 1C 8C 48 03 DD 48 3B DE 72 ?? }
		$chunk_2 = { 48 8B C4 48 89 48 ?? 48 89 50 ?? 4C 89 40 ?? 4C 89 48 ?? C3 }
		$chunk_3 = { 48 8B 45 ?? BB 01 00 00 00 48 89 07 8B 45 ?? 89 47 ?? 4C 8D 9C 24 ?? ?? ?? ?? 8B C3 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 5D C3 }
		$chunk_4 = { 48 39 3B 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 5B ?? 49 8B 73 ?? 40 0F 95 C7 8B C7 49 8B 7B ?? 49 8B E3 5D C3 }
		$chunk_5 = { BE 02 00 00 00 4C 8D 9C 24 ?? ?? ?? ?? 8B C6 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 41 5F 41 5E 41 5D 41 5C 5D C3 }
		$chunk_6 = { 43 8B 84 FE ?? ?? ?? ?? 48 03 C6 48 3B D8 73 ?? }
		$chunk_7 = { 88 02 48 FF C2 48 FF C3 8A 03 84 C0 75 ?? EB ?? }

	condition:
		4 of them
}
