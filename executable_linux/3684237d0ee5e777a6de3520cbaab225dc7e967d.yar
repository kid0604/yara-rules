rule Linux_Cryptominer_Generic_54357231
{
	meta:
		author = "Elastic Security"
		id = "54357231-23d8-44f5-94d7-71da02a8ba38"
		fingerprint = "8bbba49c863bc3d53903b1a204851dc656f3e3d68d3c8d5a975ed2dc9e797e13"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 73 F2 06 C5 F9 EB C2 C4 E3 79 16 E0 02 C4 E3 79 16 E2 03 C5 F9 70 }

	condition:
		all of them
}
