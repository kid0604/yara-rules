rule Linux_Trojan_Getshell_213d4d69
{
	meta:
		author = "Elastic Security"
		id = "213d4d69-5660-468d-a98c-ff3eef604b1e"
		fingerprint = "60e385e4c5eb189785bc14d39bf8a22c179e4be861ce3453fbcf4d367fc87c90"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Getshell"
		reference = "05fc4dcce9e9e1e627ebf051a190bd1f73bc83d876c78c6b3d86fc97b0dfd8e8"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Getshell"
		filetype = "executable"

	strings:
		$a = { EC 01 00 00 00 EB 3C 8B 45 EC 48 98 48 C1 E0 03 48 03 45 D0 48 }

	condition:
		all of them
}
