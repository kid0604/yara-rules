rule Windows_Ransomware_Cuba_e64a16b1
{
	meta:
		author = "Elastic Security"
		id = "e64a16b1-262c-4835-bd95-4dde89dd75f4"
		fingerprint = "840f2ebe2664db9a0918acf7d408ca8060ee0d3c330ad08b36e5be7f7e2cf069"
		creation_date = "2021-08-04"
		last_modified = "2021-10-04"
		threat_name = "Windows.Ransomware.Cuba"
		reference_sample = "33352a38454cfc247bc7465bf177f5f97d7fd0bd220103d4422c8ec45b4d3d0e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Cuba"
		filetype = "executable"

	strings:
		$a = { 45 EC 8B F9 8B 45 14 89 45 F0 8D 45 E4 50 8D 45 F8 66 0F 13 }
		$HeaderCheck = { 8B 06 81 38 46 49 44 45 75 ?? 81 78 04 4C 2E 43 41 74 }

	condition:
		any of them
}
