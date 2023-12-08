rule Linux_Trojan_Sshdoor_97f92ff7
{
	meta:
		author = "Elastic Security"
		id = "97f92ff7-b14f-4cdf-aef7-d1ca3e46ae48"
		fingerprint = "4ad5b6b259655bf1bf58d662cf3daf3fec6ba61fcff36e24e8d239e99a8bd36f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Sshdoor"
		reference_sample = "2e1d909e4a6ba843194f9912826728bd2639b0f34ee512e0c3c9e5ce4d27828e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Sshdoor"
		filetype = "executable"

	strings:
		$a = { C0 75 C3 48 8B 44 24 08 64 48 33 04 25 28 00 00 00 75 07 48 83 }

	condition:
		all of them
}
