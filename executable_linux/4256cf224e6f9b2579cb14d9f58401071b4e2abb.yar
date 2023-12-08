rule Linux_Exploit_Local_30c21b03
{
	meta:
		author = "Elastic Security"
		id = "30c21b03-22fc-4ec8-8b65-084e98da8d8d"
		fingerprint = "8112c4a9bce4b4c9407e851849a5850fa36591570694950a4b53e8a09a1dd92b"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "a09c81f185a4ceed134406fa7fefdfa7d8dfc10d639dd044c94fbb6d570fa029"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { 1B CD 80 31 DB 89 D8 B0 17 CD 80 31 C0 50 50 B0 }

	condition:
		all of them
}
