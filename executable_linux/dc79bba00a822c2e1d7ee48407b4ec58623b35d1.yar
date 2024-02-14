rule Linux_Generic_Threat_80aea077
{
	meta:
		author = "Elastic Security"
		id = "80aea077-c94f-4c95-83a5-967cc16df2a8"
		fingerprint = "702953af345afb999691906807066d58b9ec055d814fc6fe351e59ac5193e31f"
		creation_date = "2024-01-17"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "002827c41bc93772cd2832bc08dfc413302b1a29008adbb6822343861b9818f0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 38 49 89 FE 0F B6 0E 48 C1 E1 18 0F B6 6E 01 48 C1 E5 10 48 09 E9 0F B6 6E 03 48 09 E9 0F B6 6E 02 48 C1 E5 08 48 09 CD 0F B6 56 04 48 C1 E2 18 44 0F B6 7E 05 49 C1 E7 10 4C 09 FA 44 }

	condition:
		all of them
}
