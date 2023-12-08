rule Linux_Hacktool_Flooder_f454ec10
{
	meta:
		author = "Elastic Security"
		id = "f454ec10-7a67-4717-9e95-fecb7c357566"
		fingerprint = "2ae5e2c3190a4ce5d238efdb10ac0520987425fb7af52246b6bf948abd0259da"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Hacktool.Flooder"
		reference = "0297e1ad6e180af85256a175183102776212d324a2ce0c4f32e8a44a2e2e9dad"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 8B 45 EC 48 63 D0 48 8B 45 D0 48 01 D0 0F B6 00 3C 2E 75 4D 8B }

	condition:
		all of them
}
