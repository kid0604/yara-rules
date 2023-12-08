rule Linux_Trojan_Ngioweb_7926bc8e
{
	meta:
		author = "Elastic Security"
		id = "7926bc8e-110f-4b8a-8cc5-003732b6fcfd"
		fingerprint = "246e06d73a3a61ade6ac5634378489890a5585e84be086e0a81eb7586802e98f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ngioweb"
		reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ngioweb with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { ED 74 31 48 8B 5B 10 4A 8D 6C 3B FC 48 39 EB 77 23 8B 3B 48 83 }

	condition:
		all of them
}
