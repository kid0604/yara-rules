rule Linux_Cryptominer_Xmrig_73faf972
{
	meta:
		author = "Elastic Security"
		id = "73faf972-43e4-448d-bdfd-cda9be15fce6"
		fingerprint = "f31c2658acd6d13ae000426d3845bcec7a8a587bbaed75173baa84b2871b0b42"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrig"
		filetype = "executable"

	strings:
		$a = { 6F C4 83 E0 01 83 E1 06 09 C1 44 89 E8 01 C9 D3 }

	condition:
		all of them
}
