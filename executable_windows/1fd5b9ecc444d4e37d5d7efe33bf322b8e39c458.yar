rule Windows_Exploit_CVE_2022_38028_31fdb122
{
	meta:
		author = "Elastic Security"
		id = "31fdb122-36fd-4fae-b605-542dc344575c"
		fingerprint = "e489287412ee673f4d93c5efc9e61b5d26d877bb0f4ddf827926b4d5d87dc399"
		creation_date = "2024-06-06"
		last_modified = "2024-06-12"
		threat_name = "Windows.Exploit.CVE-2022-38028"
		reference_sample = "6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows exploit for CVE-2022-38028"
		filetype = "executable"

	strings:
		$a = { 70 72 69 6E 74 54 69 63 6B 65 74 2E 58 6D 6C 4E 6F 64 65 2E 6C 6F 61 64 28 27 25 53 3A 2F 2F 67 6F 27 29 3B }

	condition:
		all of them
}
