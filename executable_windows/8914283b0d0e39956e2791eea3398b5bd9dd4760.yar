rule Windows_Generic_MalCert_101ac60e
{
	meta:
		author = "Elastic Security"
		id = "101ac60e-70e0-4946-a6f3-90dac6db2baf"
		fingerprint = "2ce306f3a339649d5536de2cd127f3f7dbadbb0bebcb3dccd1e4bfcde99b4191"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "05c02be58b84139a25c8cd8662efd3a377765a0d69ab206aa6b17e22904ebc9e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 77 28 6A 4C BB 8C 2A D8 CD E8 4A AD }

	condition:
		all of them
}
