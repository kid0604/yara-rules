rule Linux_Trojan_Sshdoor_cde7cfd4
{
	meta:
		author = "Elastic Security"
		id = "cde7cfd4-a664-481d-8865-d44332c7f243"
		fingerprint = "65bf31705755b19b1c01bd2bcc00525469c8cd35eaeff51d546a1d0667d8a615"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Sshdoor"
		reference_sample = "cd646a1d59c99b9e038098b91cdb63c3fe9b35bb10583bef0ab07260dbd4d23d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Sshdoor with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 75 CC 8B 73 08 48 8B 54 24 08 48 83 C4 18 5B 5D 41 5C 41 5D 4C }

	condition:
		all of them
}
