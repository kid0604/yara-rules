rule Linux_Hacktool_Flooder_af9f75e6
{
	meta:
		author = "Elastic Security"
		id = "af9f75e6-9a9b-4e03-9c76-8c0c9f07c8b1"
		fingerprint = "f6e7d6e9c03c8ce3e14b214fe268e7aab2e15c1b4378fe253021497fb9a884e6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 C0 C7 45 B4 14 00 }

	condition:
		all of them
}
