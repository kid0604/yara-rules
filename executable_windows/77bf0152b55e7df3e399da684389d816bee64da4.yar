rule Windows_Trojan_Qbot_7d5dc64a
{
	meta:
		author = "Elastic Security"
		id = "7d5dc64a-a597-44ac-a0fd-cefffc5e9cff"
		fingerprint = "ab80d96a454e0aad56621e70be4d55f099c41b538a380feb09192d252b4db5aa"
		creation_date = "2021-10-04"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Qbot"
		reference_sample = "a2bacde7210d88675564106406d9c2f3b738e2b1993737cb8bf621b78a9ebf56"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Qbot"
		filetype = "executable"

	strings:
		$a1 = "%u.%u.%u.%u.%u.%u.%04x" ascii fullword
		$a2 = "stager_1.dll" ascii fullword

	condition:
		all of them
}
