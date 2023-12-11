rule Linux_Exploit_Pulse_2bea17e8
{
	meta:
		author = "Elastic Security"
		id = "2bea17e8-2324-4502-9ced-7a45d94099ec"
		fingerprint = "4d57fb355e7d68ad3da26ff3bade291ebbfa8df5f0727579787e33ebee888d41"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Pulse"
		reference_sample = "c29cb4c2d83127cf4731573a7fac531f90f27799857f5e250b9f71362108f559"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Pulse"
		filetype = "executable"

	strings:
		$a = { 89 E5 48 8D 45 F8 48 89 45 F8 48 8B 45 F8 48 25 00 F0 FF FF 48 }

	condition:
		all of them
}
