rule Linux_Trojan_Xorddos_71f8e26c
{
	meta:
		author = "Elastic Security"
		id = "71f8e26c-d0ff-49e8-9c20-8df9149e8843"
		fingerprint = "dbd1275bd01fb08342e60cb0c20adaf42971ed6ee0f679fedec9bc6967ecc015"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "13f873f83b84a0d38eb3437102f174f24a0ad3c5a53b83f0ee51c62c29fb1465"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 24 8D 64 24 04 1B 07 87 DA 8B 5D F4 52 87 DA 5B 83 C2 03 52 8B 54 }

	condition:
		all of them
}
