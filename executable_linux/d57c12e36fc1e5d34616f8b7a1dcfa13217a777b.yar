rule Linux_Trojan_Psybnc_ab3396d5
{
	meta:
		author = "Elastic Security"
		id = "ab3396d5-388b-4730-9a55-581c327a2769"
		fingerprint = "1180e02d3516466457f48dc614611a6949a4bf21f6a294f6384892db30dc4171"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Psybnc"
		reference_sample = "c5ec84e7cc891af25d6319abb07b1cedd90b04cbb6c8656c60bcb07e60f0b620"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Psybnc"
		filetype = "executable"

	strings:
		$a = { 53 54 00 55 53 45 52 4F 4E 00 30 00 50 25 64 00 58 30 31 00 }

	condition:
		all of them
}
