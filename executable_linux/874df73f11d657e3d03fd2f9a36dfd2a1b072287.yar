rule Linux_Exploit_Moogrey_81131b66
{
	meta:
		author = "Elastic Security"
		id = "81131b66-788e-4456-9cb4-ffade713e8d4"
		fingerprint = "d21e48c7afe580a764153ca489c24a7039ae663ebb281a4605f3a230a963e33e"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Moogrey"
		reference_sample = "cc27b9755bd9feb1fb2c510f66e36c20a1503e6769cdaeee2bea7fe962d22ccc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Moogrey malware"
		filetype = "executable"

	strings:
		$a = { 89 C0 89 45 D4 83 7D D4 00 79 1A 83 EC 0C 68 50 }

	condition:
		all of them
}
