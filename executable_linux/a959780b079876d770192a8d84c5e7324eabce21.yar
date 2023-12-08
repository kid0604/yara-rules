rule Linux_Trojan_Tsunami_d9e6b88e
{
	meta:
		author = "Elastic Security"
		id = "d9e6b88e-256c-4e9d-a411-60b477b70446"
		fingerprint = "8fc61c0754d1a8b44cefaf2dbd937ffa0bb177d98b071347d2f9022181555b7a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "a4ac275275e7be694a200fe6c5c5746256398c109cf54f45220637fe5d9e26ba"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 04 02 01 20 03 20 02 C9 07 40 4E 00 60 01 C0 04 17 B6 92 07 }

	condition:
		all of them
}
