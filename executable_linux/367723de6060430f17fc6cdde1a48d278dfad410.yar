rule Linux_Trojan_Gafgyt_dd0d6173
{
	meta:
		author = "Elastic Security"
		id = "dd0d6173-b863-45cf-9348-3375a4e624cf"
		fingerprint = "5e2cb111c2b712951b71166111d339724b4f52b93f90cb474f1e67598212605f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID dd0d6173"
		filetype = "executable"

	strings:
		$a = { 55 F8 8B 45 F0 89 42 0C 48 8B 55 F8 8B 45 F4 89 42 10 C9 C3 55 48 }

	condition:
		all of them
}
