rule Linux_Trojan_Mirai_d18b3463
{
	meta:
		author = "Elastic Security"
		id = "d18b3463-1b5e-49e1-9ae8-1d63a10a1ccc"
		fingerprint = "4b3d3bb65db2cdb768d91c50928081780f206208e952c74f191d8bc481ce19c6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "cd86534d709877ec737ceb016b2a5889d2e3562ffa45a278bc615838c2e9ebc3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Trojan.Mirai malware"
		filetype = "executable"

	strings:
		$a = { DF 77 95 8D 42 FA 3C 01 76 8E 80 FA 0B 74 89 80 FA 15 74 84 80 }

	condition:
		all of them
}
