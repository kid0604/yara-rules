rule Linux_Generic_Threat_47b147ec
{
	meta:
		author = "Elastic Security"
		id = "47b147ec-bcd2-423a-bc67-a85712d135eb"
		fingerprint = "38f55b825bbd1fa837b2b9903d01141a071539502fe21b874948dbc5ac215ae8"
		creation_date = "2024-02-01"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "cc7734a10998a4878b8f0c362971243ea051ce6c1689444ba6e71aea297fb70d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 50 41 54 48 3D 2F 62 69 6E 3A 2F 73 62 69 6E 3A 2F 75 73 72 2F 73 62 69 6E 3A 2F 75 73 72 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 73 62 69 6E }

	condition:
		all of them
}
