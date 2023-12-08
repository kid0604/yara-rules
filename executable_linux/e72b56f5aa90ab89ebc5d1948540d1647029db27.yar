rule Linux_Trojan_Sshdoor_5b78aa01
{
	meta:
		author = "Elastic Security"
		id = "5b78aa01-c5d4-4281-9a2e-e3f0d3df31d3"
		fingerprint = "19369c825bc8052bfc234a457ee4029cf48bf3b5b9a008a1a6c2680b97ae6284"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Sshdoor"
		reference_sample = "2e1d909e4a6ba843194f9912826728bd2639b0f34ee512e0c3c9e5ce4d27828e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Sshdoor"
		filetype = "executable"

	strings:
		$a = { 11 75 39 41 0F B6 77 01 4C 89 E2 40 84 F6 74 2C 40 80 FE 5A }

	condition:
		all of them
}
