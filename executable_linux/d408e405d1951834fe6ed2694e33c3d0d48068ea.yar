rule Linux_Exploit_CVE_2012_0056_a1e53450
{
	meta:
		author = "Elastic Security"
		id = "a1e53450-036e-4ae3-bfe4-64a6c7239a04"
		fingerprint = "d0a0635fb356ccedb1448082cc63748d49d45f8a25e43eab7ac1d67e87062b8f"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2012-0056"
		reference_sample = "15a4d149e935758199f6df946ff889e12097f5fec4ef450e9cbd554d1efbd5e6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux exploit for CVE-2012-0056"
		filetype = "executable"

	strings:
		$a = { 80 31 C9 B3 ?? B1 02 B0 3F CD 80 31 C0 50 68 6E }

	condition:
		all of them
}
