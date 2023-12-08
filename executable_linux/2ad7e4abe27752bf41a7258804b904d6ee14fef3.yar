rule Linux_Trojan_Gafgyt_862c4e0e
{
	meta:
		author = "Elastic Security"
		id = "862c4e0e-83a4-458b-8c00-f2f3cf0bf9db"
		fingerprint = "2a6b4f8d8fb4703ed26bdcfbbb5c539dc451c8b90649bee80015c164eae4c281"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 862c4e0e"
		filetype = "executable"

	strings:
		$a = { 02 89 45 F8 8B 45 F8 C1 E8 10 85 C0 75 E6 8B 45 F8 F7 D0 0F }

	condition:
		all of them
}
