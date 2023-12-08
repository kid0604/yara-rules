rule MacOS_Trojan_Thiefquest_fc2e1271
{
	meta:
		author = "Elastic Security"
		id = "fc2e1271-3c96-4c93-9e3d-212782928e6e"
		fingerprint = "195e8f65e4ea722f0e1ba171f2ad4ded97d4bc97da38ef8ac8e54b8719e4c5ae"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Thiefquest"
		reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Thiefquest"
		filetype = "executable"

	strings:
		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 30 30 30 42 67 7B 30 30 }

	condition:
		all of them
}
