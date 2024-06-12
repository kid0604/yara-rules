rule Linux_Generic_Threat_3bcc1630
{
	meta:
		author = "Elastic Security"
		id = "3bcc1630-cfa4-4f2e-b129-f0150595dbc3"
		fingerprint = "0e4fe564c5c3c04e4b40af2bebb091589fb52292bd16a78b733c67968fa166e7"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "62a6866e924af2e2f5c8c1f5009ce64000acf700bb5351a47c7cfce6a4b2ffeb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2F 72 6F 6F 74 2F 64 76 72 5F 67 75 69 2F }
		$a2 = { 2F 72 6F 6F 74 2F 64 76 72 5F 61 70 70 2F }
		$a3 = { 73 74 6D 5F 68 69 33 35 31 31 5F 64 76 72 }

	condition:
		all of them
}
