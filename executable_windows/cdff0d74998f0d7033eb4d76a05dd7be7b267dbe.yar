rule Windows_Trojan_BloodAlchemy_e510798d
{
	meta:
		author = "Elastic Security"
		id = "e510798d-a938-47ba-92e3-0c1bcd3ce9a9"
		fingerprint = "151519156e4c6b5395c03f70c77601681f17f86a08db96a622b9489a3df682d6"
		creation_date = "2023-09-25"
		last_modified = "2023-09-25"
		threat_name = "Windows.Trojan.BloodAlchemy"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan BloodAlchemy"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 83 EC 54 53 8B 5D 08 56 57 33 FF 89 55 F4 89 4D F0 BE 00 00 00 02 89 7D F8 89 7D FC 85 DB }
		$a2 = { 55 8B EC 83 EC 0C 56 57 33 C0 8D 7D F4 AB 8D 4D F4 AB AB E8 42 10 00 00 8B 7D F4 33 F6 85 FF 74 03 8B 77 08 }

	condition:
		any of them
}
