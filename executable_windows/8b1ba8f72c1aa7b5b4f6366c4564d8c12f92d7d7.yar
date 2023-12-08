rule Windows_Ransomware_Darkside_d7fc4594
{
	meta:
		author = "Elastic Security"
		id = "d7fc4594-185c-4afb-986e-5718c0beabf1"
		fingerprint = "90444cd2d3a38296b4979f91345a9999b0032f6c0abee6ff7c15d149b59e5e88"
		creation_date = "2021-05-20"
		last_modified = "2021-10-04"
		threat_name = "Windows.Ransomware.Darkside"
		reference_sample = "bfb31c96f9e6285f5bb60433f2e45898b8a7183a2591157dc1d766be16c29893"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Darkside variant d7fc4594"
		filetype = "executable"

	strings:
		$a1 = { 5F 30 55 56 BD 0A 00 00 00 8B 07 8B 5F 10 8B 4F 20 8B 57 30 }

	condition:
		any of them
}
