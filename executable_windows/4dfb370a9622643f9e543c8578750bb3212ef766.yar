rule Windows_Ransomware_Nightsky_253c4d0d
{
	meta:
		author = "Elastic Security"
		id = "253c4d0d-157f-4929-9f0e-5830ebc377dc"
		fingerprint = "739529dfb1f8c8ab2a7f6a4b2b18b27dd2fcc38eda0f110897fc6cb5d64b1c92"
		creation_date = "2022-03-14"
		last_modified = "2022-04-12"
		threat_name = "Windows.Ransomware.Nightsky"
		reference_sample = "2c940a35025dd3847f7c954a282f65e9c2312d2ada28686f9d1dc73d1c500224"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Nightsky"
		filetype = "executable"

	strings:
		$a1 = { 43 B8 48 2B D9 49 89 43 C0 4C 8B E2 49 89 43 C8 4C 8B F1 49 89 }

	condition:
		all of them
}
