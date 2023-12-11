rule Linux_Exploit_Enoket_fbf508e1
{
	meta:
		author = "Elastic Security"
		id = "fbf508e1-2a44-417e-a2e4-8d43c2b64017"
		fingerprint = "4909d3a04b820547fbff774c64c112b8a6a5e95452992639296a220776826d98"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Enoket"
		reference_sample = "d1fa8520d3c3811d29c3d5702e7e0e7296b3faef0553835c495223a2bc015214"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Enoket malware"
		filetype = "executable"

	strings:
		$a = { 45 E8 76 0F 48 8B 45 E8 48 83 E8 01 0F B6 00 3C 5F 74 DF 48 8B }

	condition:
		all of them
}
