rule Windows_Ransomware_Darkside_aceac5d9
{
	meta:
		author = "Elastic Security"
		id = "aceac5d9-fb38-4dca-ab1f-44ee40005d37"
		fingerprint = "521b0f574b27151ad03fc7693fd692e1a13e81a28e39d04d3f7ea149a0da59b9"
		creation_date = "2021-05-20"
		last_modified = "2021-10-04"
		threat_name = "Windows.Ransomware.Darkside"
		reference_sample = "bfb31c96f9e6285f5bb60433f2e45898b8a7183a2591157dc1d766be16c29893"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Darkside variant based on file fingerprint"
		filetype = "executable"

	strings:
		$a1 = { 41 54 55 53 48 83 EC 28 48 8B 1F 4C 8B 66 08 48 8D 7C 24 10 4C }

	condition:
		any of them
}
