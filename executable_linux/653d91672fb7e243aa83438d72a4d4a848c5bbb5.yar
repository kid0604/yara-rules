rule Linux_Cryptominer_Malxmr_74418ec5
{
	meta:
		author = "Elastic Security"
		id = "74418ec5-f84a-4d79-b1b0-c1d579ad7b97"
		fingerprint = "ec14cac86b2b0f75f1d01b7fb4b57bfa3365f8e4d11bfed2707b0174875d1234"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "d79ad967ac9fc0b1b6d54e844de60d7ba3eaad673ee69d30f9f804e5ccbf2880"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { F9 75 7A A8 8A 65 FC 5C E0 6E 09 4B 8F AA B3 A4 66 44 B1 D1 13 }

	condition:
		all of them
}
