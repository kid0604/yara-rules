rule Linux_Hacktool_Flooder_1a4eb229
{
	meta:
		author = "Elastic Security"
		id = "1a4eb229-a194-46a5-8e93-370a40ba999b"
		fingerprint = "de076ef23c2669512efc00ddfe926ef04f8ad939061c69131a0ef9a743639371"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { F4 8B 45 E8 83 C0 01 89 45 F8 EB 0F 8B 45 E8 83 C0 01 89 45 F4 8B }

	condition:
		all of them
}
