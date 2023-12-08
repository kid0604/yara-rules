rule Linux_Hacktool_Flooder_50158a6e
{
	meta:
		author = "Elastic Security"
		id = "50158a6e-d412-4e37-a8b5-c7c79a2a5393"
		fingerprint = "f6286d1fd84aad72cdb8c655814a9df1848fae94ae931ccf62187c100b27a349"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference = "1e0cdb655e48d21a6b02d2e1e62052ffaaec9fdfe65a3d180fc8afabc249e1d8"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 45 F8 48 01 D0 48 89 45 D8 0F B7 45 E6 48 8D 50 33 48 8B 45 F8 48 }

	condition:
		all of them
}
