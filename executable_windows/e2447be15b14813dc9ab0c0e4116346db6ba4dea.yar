rule Windows_Trojan_IcedID_7c1619e3
{
	meta:
		author = "Elastic Security"
		id = "7c1619e3-f94a-4a46-8a81-d5dd7a58c754"
		fingerprint = "ae21deaad74efaff5bec8c9010dc340118ac4c79e3bec190a7d3c3672a5a8583"
		creation_date = "2022-12-20"
		last_modified = "2023-02-01"
		description = "IcedID Injector Variant Loader "
		threat_name = "Windows.Trojan.IcedID"
		reference_sample = "4f6de748628b8b06eeef3a5fabfe486bfd7aaa92f50dc5a8a8c70ec038cd33b1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 84 C0 75 ?? 8B 74 24 ?? 81 F1 [4] 39 16 76 }
		$a2 = { D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 }
		$a3 = { 8B 4E ?? FF 74 0B ?? 8B 44 0B ?? 03 C1 50 8B 44 0B ?? 03 46 ?? 50 E8 [4] 8B 46 ?? 8D 5B ?? 83 C4 0C 47 3B 78 }

	condition:
		all of them
}
