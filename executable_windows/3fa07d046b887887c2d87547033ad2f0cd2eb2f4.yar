rule Windows_Exploit_IoRing_1e4a8f47
{
	meta:
		author = "Elastic Security"
		id = "1e4a8f47-0c04-4219-bc51-03ed0078d8a9"
		fingerprint = "a9048bd34f6dd5b7da283ff23397fa22802049fdce15915ea023b27b9b825d30"
		creation_date = "2024-02-28"
		last_modified = "2024-03-21"
		threat_name = "Windows.Exploit.IoRing"
		reference_sample = "ba2bd270bf3f312dfa3f77f0716edb634c90506c87f82c04aee09445d18738eb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows exploit IoRing"
		filetype = "executable"

	strings:
		$s1 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 69 00 6F 00 72 00 69 00 6E 00 67 00 5F 00 6F 00 75 00 74 00 }
		$s2 = "ioring_read" wide nocase
		$s3 = "ioring_write" wide nocase
		$s4 = "IoRing->RegBuffers" nocase

	condition:
		2 of them
}
