rule Linux_Trojan_Ngioweb_8bd3002c
{
	meta:
		author = "Elastic Security"
		id = "8bd3002c-d9c7-4f93-b7f0-4cb9ba131338"
		fingerprint = "2ee5432cf6ead4eca3aad70e40fac7e182bdcc74dc22dc91a12946ae4182f1ab"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ngioweb"
		reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ngioweb variant with ID 8bd3002c"
		filetype = "executable"

	strings:
		$a = { 24 18 67 8A 09 84 C9 74 0D 80 F9 2E 75 02 FF C0 FF 44 24 18 }

	condition:
		all of them
}
