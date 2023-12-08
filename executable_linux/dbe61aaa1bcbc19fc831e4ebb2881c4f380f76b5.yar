rule Linux_Cryptominer_Xmrig_77fbc695
{
	meta:
		author = "Elastic Security"
		id = "77fbc695-6fe3-4e30-bb2f-f64379ec4efd"
		fingerprint = "e0c6cb7a05c622aa40dfe2167099c496b714a3db4e9b92001bbe6928c3774c85"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "e723a2b976adddb01abb1101f2d3407b783067bec042a135b21b14d63bc18a68"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrig malware"
		filetype = "executable"

	strings:
		$a = { F2 0F 58 44 24 08 F2 0F 11 44 24 08 8B 7B 08 41 8D 76 01 49 83 }

	condition:
		all of them
}
