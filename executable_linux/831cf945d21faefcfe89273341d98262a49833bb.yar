rule Linux_Exploit_Lotoor_b293f6ec
{
	meta:
		author = "Elastic Security"
		id = "b293f6ec-0342-4727-b2a1-bd60be11ef74"
		fingerprint = "42c95bdd82e398bceeb985cff50f4613596b71024c052487f5b337bb35489594"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "d1fa8520d3c3811d29c3d5702e7e0e7296b3faef0553835c495223a2bc015214"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { B8 89 45 A8 8B 45 A8 83 C0 64 89 45 B4 EB 2A 8B 45 A8 48 98 48 C1 }

	condition:
		all of them
}
