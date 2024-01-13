rule Windows_Trojan_Afdk_5f8cc135
{
	meta:
		author = "Elastic Security"
		id = "5f8cc135-88b1-478d-aedb-0d60cee0bbf2"
		fingerprint = "275bfaac332f3cbc1164c35bdbc5cbe8bfd45559f6b929a0b8b64af2de241bd8"
		creation_date = "2023-12-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.Afdk"
		reference_sample = "6723a9489e7cfb5e2d37ff9160d55cda065f06907122d73764849808018eb7a0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Afdk"
		filetype = "executable"

	strings:
		$a1 = "Cannot set the log file name"
		$a2 = "Cannot install the hook procedure"
		$a3 = "Keylogger is up and running..."

	condition:
		2 of them
}
