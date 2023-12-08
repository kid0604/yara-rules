rule Linux_Trojan_Gognt_05b10f4b
{
	meta:
		author = "Elastic Security"
		id = "05b10f4b-7434-457a-9e8e-d898bb839dce"
		fingerprint = "fdf7b65f812c17c7f30b3095f237173475cdfb0c10a4b187f751c0599f6b5729"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gognt"
		reference_sample = "e43aaf2345dbb5c303d5a5e53cd2e2e84338d12f69ad809865f20fd1a5c2716f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gognt"
		filetype = "executable"

	strings:
		$a = { 7C 24 78 4C 89 84 24 A8 00 00 00 48 29 D7 49 89 F9 48 F7 DF 48 C1 }

	condition:
		all of them
}
