rule Linux_Trojan_Gafgyt_0535ebf7
{
	meta:
		author = "Elastic Security"
		id = "0535ebf7-844f-4207-82ef-e155ceff7a3e"
		fingerprint = "2b9b17dad296c0a58a7efa1fb3f71c62bf849f00deb978c1103ab8a480290024"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "77e18bb5479b644ba01d074057c9e2bd532717f6ab3bb88ad2b7497b85d2a5de"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint 0535ebf7"
		filetype = "executable"

	strings:
		$a = { F8 48 8B 04 24 6A 18 48 F7 14 24 48 FF 04 24 48 03 24 24 48 8D 64 }

	condition:
		all of them
}
