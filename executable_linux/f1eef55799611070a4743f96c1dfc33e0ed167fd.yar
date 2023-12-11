rule Linux_Trojan_Ngioweb_d8573802
{
	meta:
		author = "Elastic Security"
		id = "d8573802-f141-4fd1-b06a-605451a72465"
		fingerprint = "0052566dda66ae0dfa54d68f4ce03b5a2e2a442c4a18d70f16fd02303a446e66"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ngioweb"
		reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ngioweb"
		filetype = "executable"

	strings:
		$a = { 10 40 74 38 51 51 6A 02 FF 74 24 18 FF 93 C8 00 00 00 83 C4 }

	condition:
		all of them
}
