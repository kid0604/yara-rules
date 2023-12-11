rule Linux_Trojan_Ngioweb_b97e0253
{
	meta:
		author = "Elastic Security"
		id = "b97e0253-497f-4c2c-9d4c-ad89af64847f"
		fingerprint = "859f29acec8bb05b8a8e827af91e927db0b2390410179a0f5b03e7f71af64949"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ngioweb"
		reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ngioweb"
		filetype = "executable"

	strings:
		$a = { 41 5C 41 5D 41 5E 41 5F C3 67 0F BE 17 39 F2 74 12 84 D2 74 04 }

	condition:
		all of them
}
