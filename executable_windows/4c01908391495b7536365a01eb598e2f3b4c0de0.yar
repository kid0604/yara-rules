rule Windows_Exploit_Perfusion_5ab5ddee
{
	meta:
		author = "Elastic Security"
		id = "5ab5ddee-e79b-4f1c-bd60-92793f14e490"
		fingerprint = "c8d13213b20fc99dd71034ddae986c71f6e89f632655e88d5f9c8be1d72c6231"
		creation_date = "2024-02-28"
		last_modified = "2024-03-21"
		threat_name = "Windows.Exploit.Perfusion"
		reference_sample = "7fdef25acb0d1447203b9768ae58a8e21db24816c602b160d105dab86ae34728"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Exploit.Perfusion"
		filetype = "executable"

	strings:
		$s1 = "SYSTEM\\CurrentControlSet\\Services\\%ws\\Performance" wide
		$s2 = "Win32_Perf" wide
		$s3 = "CollectPerfData" wide
		$s4 = "%wsperformance_%d_%d_%d.dll" wide

	condition:
		all of them
}
