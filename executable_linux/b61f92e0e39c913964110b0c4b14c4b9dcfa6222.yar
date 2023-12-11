rule Linux_Hacktool_Flooder_4bcea1c4
{
	meta:
		author = "Elastic Security"
		id = "4bcea1c4-de08-4526-8d31-89c5512f07af"
		fingerprint = "e859966e8281e024c82dedd5bd237ab53af28a0cb21d24daa456e5cd1186c352"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 50 FF 48 8B 45 C0 48 01 D0 0F B6 00 3C 0A 74 22 48 8B 45 C0 48 }

	condition:
		all of them
}
