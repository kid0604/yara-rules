rule Linux_Trojan_Xorddos_7909cdd2
{
	meta:
		author = "Elastic Security"
		id = "7909cdd2-8a49-4f51-ae16-1ffe321a29d4"
		fingerprint = "5c982596276c8587a88bd910bb2e75a7f72ea7a57c401ffa387aced33f9ac2b9"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "0a4a5874f43adbe71da88dc0ef124f1bf2f4e70d0b1b5461b2788587445f79d9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { A5 07 00 EC C5 19 08 EC C5 19 08 18 06 00 00 18 06 00 00 06 }

	condition:
		all of them
}
