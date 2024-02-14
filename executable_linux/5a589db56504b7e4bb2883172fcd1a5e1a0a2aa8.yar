rule Linux_Generic_Threat_08e4ee8c
{
	meta:
		author = "Elastic Security"
		id = "08e4ee8c-4dfd-4bb8-9406-dce6fb7bc9ee"
		fingerprint = "5e71d8515def09e95866a08951dd06bb84d327489f000e1c2326448faad15753"
		creation_date = "2024-01-18"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "35eeba173fb481ac30c40c1659ccc129eae2d4d922e27cf071047698e8d95aea"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 78 63 72 79 70 74 6F 67 72 61 70 68 79 2D 32 2E 31 2E 34 2D 70 79 32 2E 37 2E 65 67 67 2D 69 6E 66 6F 2F 50 4B 47 2D 49 4E 46 4F }

	condition:
		all of them
}
