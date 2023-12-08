rule Linux_Cryptominer_Xmrig_dbcc9d87
{
	meta:
		author = "Elastic Security"
		id = "dbcc9d87-5064-446d-9581-b14cf183ec3f"
		fingerprint = "ebb6d184d7470437aace81d55ada5083e55c0de67e566b052245665aeda96d69"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "da9b8fb5c26e81fb3aed3b0bc95d855339fced303aae2af281daf0f1a873e585"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Xmrig malware"
		filetype = "executable"

	strings:
		$a = { 78 72 47 47 58 34 53 58 5F 34 74 43 41 66 30 5A 57 73 00 64 48 8B 0C 25 F8 FF }

	condition:
		all of them
}
