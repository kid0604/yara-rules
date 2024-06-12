rule Linux_Generic_Threat_1973391f
{
	meta:
		author = "Elastic Security"
		id = "1973391f-b9a2-465d-8990-51c6e9fab84b"
		fingerprint = "90a261afd81993057b084c607e27843ff69649b3d90f4d0b52464e87fdf2654d"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "7bd76010f18061aeaf612ad96d7c03341519d85f6a1683fc4b2c74ea0508fe1f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 70 69 63 6B 75 70 20 2D 6C 20 2D 74 20 66 69 66 6F 20 2D 75 }
		$a2 = { 5B 2D 5D 20 43 6F 6E 6E 65 63 74 20 66 61 69 6C 65 64 2E }

	condition:
		all of them
}
