rule Linux_Trojan_Ngioweb_a592a280
{
	meta:
		author = "Elastic Security"
		id = "a592a280-053f-47bc-8d74-3fa5d74bd072"
		fingerprint = "60f5ddd115fa1abac804d2978bbb8d70572de0df9da80686b5652520c03bd1ee"
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
		$a = { 75 06 8B 7C 24 2C EB 2C 83 FD 01 75 06 8B 7C 24 3C EB 21 83 }

	condition:
		all of them
}
