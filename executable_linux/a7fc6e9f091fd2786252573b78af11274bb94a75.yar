rule Linux_Trojan_Patpooty_f90c7e43
{
	meta:
		author = "Elastic Security"
		id = "f90c7e43-0c32-487f-a7c2-8290b341019c"
		fingerprint = "b0b0fd8da224bcd1c048c5578ed487d119f9bff4fb465f77d3043cf77d904f3d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Patpooty"
		reference_sample = "79475a66be8741d9884bc60f593c81a44bdb212592cd1a7b6130166a724cb3d3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Patpooty"
		filetype = "executable"

	strings:
		$a = { C2 48 39 C2 75 F1 C7 43 58 01 00 00 00 C7 43 54 01 00 00 00 C7 43 50 01 00 }

	condition:
		all of them
}
