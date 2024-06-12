rule Linux_Generic_Threat_e24558e1
{
	meta:
		author = "Elastic Security"
		id = "e24558e1-1337-4566-8816-9b83cbaccbf6"
		fingerprint = "04ca7e3775e3830a3388a4ad83a5e0256992c9f7beb4b59defcfb684d8471122"
		creation_date = "2024-05-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "9f483ddd8971cad4b25bb36a5a0cfb95c35a12c7d5cb9124ef0cfd020da63e99"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic threats on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 77 66 6F 66 60 6C 6E 62 67 6E 6A 6D }
		$a2 = { 62 67 6E 6A 6D 77 66 6F 66 60 6C 6E }
		$a3 = { 77 62 59 79 43 31 30 37 3A 36 3B 36 3A }

	condition:
		all of them
}
