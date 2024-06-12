rule Linux_Generic_Threat_900ffdd4
{
	meta:
		author = "Elastic Security"
		id = "900ffdd4-085e-4d6b-af7b-2972157dcefd"
		fingerprint = "f03d39e53b06dd896bfaff7c94beaa113df1831dc397ef0ea8bea63156316a1b"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "a3e1a1f22f6d32931d3f72c35a5ee50092b5492b3874e9e6309d015d82bddc5d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 20 48 89 7D E8 89 75 E4 48 83 7D E8 00 74 5C C7 45 FC 00 00 00 00 EB 3D 8B 45 FC 48 98 48 C1 E0 04 48 89 C2 48 8B 45 E8 48 01 D0 48 8B 00 48 85 C0 74 1E 8B 45 FC 48 98 48 C1 E0 04 48 }

	condition:
		all of them
}
