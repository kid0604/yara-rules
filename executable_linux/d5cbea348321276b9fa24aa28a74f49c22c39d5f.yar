rule Linux_Cryptominer_Xmrig_af809eea
{
	meta:
		author = "Elastic Security"
		id = "af809eea-fe42-4495-b7e5-c22b39102fcd"
		fingerprint = "373d2f57aede0b41296011d12b59ac006f6cf0e2bd95163f518e6e252459411b"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Xmrig af809eea variant"
		filetype = "executable"

	strings:
		$a = { 83 E0 01 83 E1 06 09 C1 44 89 ?? 01 C9 D3 }

	condition:
		all of them
}
