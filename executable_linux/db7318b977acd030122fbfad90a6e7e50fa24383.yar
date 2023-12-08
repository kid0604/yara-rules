rule Linux_Trojan_Mirai_ac253e4f
{
	meta:
		author = "Elastic Security"
		id = "ac253e4f-b628-4dd0-91f1-f19099286992"
		fingerprint = "e2eee1f72b8c2dbf68e57b721c481a5cd85296e844059decc3548e7a6dc28fea"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant ac253e4f"
		filetype = "executable"

	strings:
		$a = { 00 31 C9 EB 0A 6B C1 0A 0F BE D2 8D 4C 02 D0 8A 17 48 FF C7 8D }

	condition:
		all of them
}
