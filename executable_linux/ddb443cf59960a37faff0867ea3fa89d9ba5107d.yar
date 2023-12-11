rule Linux_Trojan_Mirai_c6055dc9
{
	meta:
		author = "Elastic Security"
		id = "c6055dc9-316b-478d-9997-1dbf455cafcc"
		fingerprint = "b95f582edf2504089ddd29ef1a0daf30644b364f3d90ede413a2aa777c205070"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "c1718d7fdeef886caa33951e75cbd9139467fa1724605fdf76c8cdb1ec20e024"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 83 7F 43 80 77 39 CF 7E 09 83 C8 FF 5A 5D 8A 0E }

	condition:
		all of them
}
