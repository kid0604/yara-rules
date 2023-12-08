rule Windows_Trojan_BloodAlchemy_de591c5a
{
	meta:
		author = "Elastic Security"
		id = "de591c5a-95a5-4a23-bc02-7bc487b6ca4b"
		fingerprint = "6765378490707c5965dc4abd04169d4a94b787be3fccf3b77f1eff5d507090a4"
		creation_date = "2023-09-25"
		last_modified = "2023-11-02"
		threat_name = "Windows.Trojan.BloodAlchemy"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan BloodAlchemy"
		filetype = "executable"

	strings:
		$crypto_0 = { 32 C7 8A DF 88 04 39 8B C1 6A 05 59 F7 F1 8A C7 8D 4A 01 D2 E3 B1 07 2A CA D2 E8 8B 4D F8 0A D8 02 FB 41 }
		$crypto_1 = { 8A 1F 0F B6 C3 83 E0 7F D3 E0 99 09 55 ?? 0B F0 47 84 DB 79 ?? 83 C1 07 83 F9 3F }
		$crypto_2 = { E8 [4] 03 F0 33 D2 8B C6 89 75 ?? 25 FF FF FF 7F 6A 34 59 F7 F1 8B 45 ?? 66 8B 0C 55 [4] 66 89 0C 43 40 89 45 ?? 3B C7 }
		$crypto_3 = { 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6A 00 6B 00 6C 00 6D 00 6E 00 6F 00 70 00 71 00 72 00 73 00 74 00 }
		$com_tm_cid = { 9F 36 87 0F E5 A4 FC 4C BD 3E 73 E6 15 45 72 DD }
		$com_tm_iid = { C0 C7 A4 AB 2F A9 4D 13 40 96 97 20 CC 3F D4 0F 85 }

	condition:
		any of ($crypto_*) and all of ($com_tm_*)
}
