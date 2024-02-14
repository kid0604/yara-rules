rule Linux_Generic_Threat_92064b27
{
	meta:
		author = "Elastic Security"
		id = "92064b27-f1c7-4b86-afc9-3dcfab69fe0d"
		fingerprint = "7a465615646184f5ab30d9b9b286f6e8a95cfbfa0ee780915983ec1200fd2553"
		creation_date = "2024-01-17"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "8e5cfcda52656a98105a48783b9362bad22f61bcb6a12a27207a08de826432d9"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 89 E5 53 8B 4D 10 8B 5D 08 85 C9 74 0D 8A 55 0C 31 C0 88 14 18 40 39 C1 75 F8 5B 5D C3 90 90 55 89 E5 8B 4D 08 8B 55 0C 85 C9 74 0F 85 D2 74 0B 31 C0 C6 04 08 00 40 39 C2 75 F7 5D C3 90 90 }

	condition:
		all of them
}
