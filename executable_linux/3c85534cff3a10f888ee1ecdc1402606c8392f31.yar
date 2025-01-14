rule Linux_Rootkit_Reptile_b2ccf852
{
	meta:
		author = "Elastic Security"
		id = "b2ccf852-1b85-4fe1-b0a7-7d39f91fee1b"
		fingerprint = "77d591ebe07ffe1eada48b3c071b1c7c21f6cc16f15eb117e7bbd8fd256e9726"
		creation_date = "2024-11-13"
		last_modified = "2024-11-22"
		threat_name = "Linux.Rootkit.Reptile"
		reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Rootkit.Reptile"
		filetype = "executable"

	strings:
		$func1 = "reptile_shell"
		$func2 = "reptile_start"
		$func3 = "reptile_module"
		$func4 = "reptile_init"
		$func5 = "reptile_exit"

	condition:
		2 of ($func*)
}
