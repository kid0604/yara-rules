rule BlackTech_HIPO_headercheck
{
	meta:
		description = "HIPO_loader malware in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "9cf6825f58f4a4ad261f48f165367040a05af35d2dea27ad8b53b48bf60b09ef"
		hash2 = "abc4b6be1a799e4690a318fe631f28e5c3458c8c0ea30b3f8c9f43ff6b120e1b"
		os = "windows"
		filetype = "executable"

	strings:
		$code1 = { 3D 48 49 50 4F 74 }
		$code2 = { 68 22 22 22 22 68 11 11 11 11 56 8B CD E8 }

	condition:
		all of them
}
