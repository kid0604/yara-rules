rule Linux_Cryptominer_Malxmr_bcab1e8f
{
	meta:
		author = "Elastic Security"
		id = "bcab1e8f-8a8f-4309-8e47-416861d1894c"
		fingerprint = "2106f2ba97c75468a2f25d1266053791034ff9a15d57df1ba3caf21f74b812f7"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "19df7fd22051abe3f782432398ea30f8be88cf42ef14bc301b1676f35b37cd7e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { EB D9 D3 0B EB D5 29 0B EB D1 03 48 6C 01 0B EB CA 0F AF 0B }

	condition:
		all of them
}
