rule Windows_Generic_Threat_ab01ba9e
{
	meta:
		author = "Elastic Security"
		id = "ab01ba9e-01e6-405b-8aaf-ae06a8fe2454"
		fingerprint = "dd9feb5d5756b3d3551ae21982b5e6eb189576298697b7d7d4bd042e4fc4c74f"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "2b237716d0c0c9877f54b3fa03823068728dfe0710c5b05e9808eab365a1408e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 53 3C 3B 54 24 38 74 23 45 3B 6C 24 2C }
		$a2 = { 3A 3D 3B 47 3B 55 3B 63 3B 6A 3B 7A 3B }
		$a3 = { 56 30 61 30 6B 30 77 30 7C 30 24 39 32 39 37 39 41 39 4F 39 5D 39 64 39 75 39 }

	condition:
		all of them
}
