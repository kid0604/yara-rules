rule Windows_Trojan_Blister_cb99a1df
{
	meta:
		author = "Elastic Security"
		id = "cb99a1df-756b-46fe-b657-63b4be2c0664"
		fingerprint = "7a7e189ed42019636ffccc06d61e18f2aa17bc3d43d08d50bb77c3258bc1a9a4"
		creation_date = "2021-12-21"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Blister"
		reference_sample = "0a7778cf6f9a1bd894e89f282f2e40f9d6c9cd4b72be97328e681fe32a1b1a00"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Blister"
		filetype = "executable"

	strings:
		$a1 = { 8D 45 DC 89 5D EC 50 6A 04 8D 45 F0 50 8D 45 EC 50 6A FF FF D7 }
		$a2 = { 75 F7 39 4D FC 0F 85 F3 00 00 00 64 A1 30 00 00 00 53 57 89 75 }
		$b1 = { 78 03 C3 8B 48 20 8B 50 1C 03 CB 8B 78 24 03 D3 8B 40 18 03 FB 89 4D F8 89 55 E0 89 45 E4 85 C0 74 3E 8B 09 8B D6 03 CB 8A 01 84 C0 74 17 C1 C2 09 0F BE C0 03 D0 41 8A 01 84 C0 75 F1 81 FA B2 17 EB 41 74 27 8B 4D F8 83 C7 02 8B 45 F4 83 C1 04 40 89 4D F8 89 45 F4 0F B7 C0 3B 45 E4 72 C2 8B FE 8B 45 04 B9 }

	condition:
		any of them
}
