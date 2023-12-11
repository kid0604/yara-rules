rule Linux_Trojan_Ngioweb_d57aa841
{
	meta:
		author = "Elastic Security"
		id = "d57aa841-8eb5-4765-9434-233ab119015f"
		fingerprint = "83a4eb7c8ac42097d3483bcf918823105b4ea4291a566b4184eacc2a0f3aa3a4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ngioweb"
		reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ngioweb"
		filetype = "executable"

	strings:
		$a = { 24 0C 48 89 4C 24 10 4C 89 44 24 18 66 83 F8 02 74 10 BB 10 00 }

	condition:
		all of them
}
