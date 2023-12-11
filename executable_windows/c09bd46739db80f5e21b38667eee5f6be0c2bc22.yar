rule Windows_Trojan_BloodAlchemy_3793364e
{
	meta:
		author = "Elastic Security"
		id = "3793364e-a73c-4cf0-855c-fdcdb2b88386"
		fingerprint = "b4620f360093284ae6f2296b4239227099f58f8f0cfe9f70298c84d6cbe7fa29"
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
		$a1 = { 55 8B EC 51 83 65 FC 00 53 56 57 BF 00 20 00 00 57 6A 40 FF 15 }
		$a2 = { 55 8B EC 81 EC 80 00 00 00 53 56 57 33 FF 8D 45 80 6A 64 57 50 89 7D E4 89 7D EC 89 7D F0 89 7D }

	condition:
		all of them
}
