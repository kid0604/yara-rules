rule Linux_Exploit_Perl_4a4b8a42
{
	meta:
		author = "Elastic Security"
		id = "4a4b8a42-bf26-4323-a12d-06360cd88aa3"
		fingerprint = "70ae986009e1d375a0322bf31fbae2090b7c0b6051ddd850e103e654d7b237b2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Perl"
		reference_sample = "d1fa8520d3c3811d29c3d5702e7e0e7296b3faef0553835c495223a2bc015214"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Perl exploit"
		filetype = "script"

	strings:
		$a = { 20 73 65 65 6B 69 6E 67 20 6F 75 74 20 74 68 65 20 73 6D 61 }

	condition:
		all of them
}
