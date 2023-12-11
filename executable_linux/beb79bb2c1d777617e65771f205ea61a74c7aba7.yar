rule Linux_Worm_Generic_bd64472e
{
	meta:
		author = "Elastic Security"
		id = "bd64472e-92a2-4d64-8008-b82d7ca33b1d"
		fingerprint = "1978baa7ff5457e06433fd45db098aefd39ea53d3f29e541eef54890a25a9dce"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Worm.Generic"
		reference_sample = "b3334a3b61b1a3fc14763dc3d590100ed5e85a97493c89b499b02b76f7a0a7d0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Worm.Generic"
		filetype = "executable"

	strings:
		$a = { 89 C0 89 45 EC 83 7D EC FF 75 38 68 54 90 04 08 }

	condition:
		all of them
}
