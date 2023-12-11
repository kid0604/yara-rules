rule Linux_Trojan_Patpooty_e2e0dff1
{
	meta:
		author = "Elastic Security"
		id = "e2e0dff1-bb01-437e-b138-7da3954dc473"
		fingerprint = "275ff92c5de2d2183ea8870b7353d24f026f358dc7d30d1a35d508a158787719"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Patpooty"
		reference_sample = "d38b9e76cbc863f69b29fc47262ceafd26ac476b0ae6283d3fa50985f93bedf3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Patpooty"
		filetype = "executable"

	strings:
		$a = { F0 8B 45 E4 8B 34 88 8D 7E 01 FC 31 C0 83 C9 FF F2 AE F7 D1 83 }

	condition:
		all of them
}
