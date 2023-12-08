rule Linux_Trojan_Mirai_994535c4
{
	meta:
		author = "Elastic Security"
		id = "994535c4-77a6-4cc6-b673-ce120be8d0f4"
		fingerprint = "a3753e29ecf64bef21e062b8dec96ba9066f665919d60976657b0991c55b827b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "376a2771a2a973628e22379b3dbb9a8015c828505bbe18a0c027b5d513c9e90d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 994535c4"
		filetype = "executable"

	strings:
		$a = { 20 74 07 31 C0 48 FF C3 EB EA FF C0 83 F8 08 75 F4 48 8D 73 03 }

	condition:
		all of them
}
