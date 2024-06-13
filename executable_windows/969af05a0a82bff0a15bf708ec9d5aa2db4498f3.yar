rule Windows_Exploit_Generic_e95cc41c
{
	meta:
		author = "Elastic Security"
		id = "e95cc41c-6cad-4b9c-b647-3c60e6614e25"
		fingerprint = "78f78de7cee54107ee7c3de9b152ce3a242c1408115ab0950ccdfc278ed15a19"
		creation_date = "2024-02-28"
		last_modified = "2024-06-12"
		threat_name = "Windows.Exploit.Generic"
		reference_sample = "4cce9e39c376f67c16df3bcd69efd9b7472c3b478e2e5ef347e1410f1105c38d"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Exploit.Generic"
		filetype = "executable"

	strings:
		$s1 = "Got system privileges" nocase
		$s2 = "Got SYSTEM token" nocase
		$s3 = "Got a SYSTEM token" nocase
		$s4 = "] Duplicating SYSTEM token" nocase
		$s5 = "] Token Stealing is successful" nocase
		$s6 = "] Exploit completed" nocase
		$s7 = "] Got SYSTEM shell." nocase
		$s8 = "] Spawning SYSTEM shell" nocase
		$s9 = "we have a SYSTEM shell!" nocase
		$s10 = "Dropping to System Shell." nocase
		$s11 = "] Enjoy the NT AUTHORITY\\SYSTEM shell" nocase
		$s12 = "] SMEP is disabled" nocase
		$s13 = "] KUSER_SHARED_DATA"
		$s14 = "] Found System EPROCESS"

	condition:
		any of them
}
