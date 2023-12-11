rule Linux_Exploit_Alie_e69de1ee
{
	meta:
		author = "Elastic Security"
		id = "e69de1ee-294d-437e-a943-abb731842523"
		fingerprint = "01fa5343fa0fb60c320f9fa49beb9c7a8a821ace7f1d6e48ea103e746b3f27a2"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Alie"
		reference_sample = "882839549f062ab4cbe6df91336ed320eaf6c2300fc2ed64d1877426a0da567d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Alie"
		filetype = "executable"

	strings:
		$a = { 0C 8D 4B 08 8D 53 0C B0 0B CD 80 89 C3 31 C0 B0 }

	condition:
		all of them
}
