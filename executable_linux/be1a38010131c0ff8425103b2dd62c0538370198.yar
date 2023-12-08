rule Linux_Cryptominer_Generic_3a8d0974
{
	meta:
		author = "Elastic Security"
		id = "3a8d0974-384e-4d62-9aa8-0bd8f7d50206"
		fingerprint = "60cb81033461e73fcb0fb8cafd228e2c9478c132f49e115c5e55d5579500caa2"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference = "193fe9ea690759f8e155458ef8f8e9efe9efc8c22ec8073bbb760e4f96b5aef7"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 07 41 89 34 06 48 83 C0 04 48 83 F8 20 75 EF 8B 42 D4 66 0F }

	condition:
		all of them
}
