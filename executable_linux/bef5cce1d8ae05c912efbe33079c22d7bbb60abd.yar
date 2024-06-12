rule Linux_Trojan_Metasploit_47f4b334
{
	meta:
		author = "Elastic Security"
		id = "47f4b334-619b-4b9c-841d-b00c09dd98e5"
		fingerprint = "955d65f1097ec9183db8bd3da43090f579a27461ba345bb74f62426734731184"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x86 msfvenom exec payloads"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "c3821f63a7ec8861a6168b4bb494bf8cbac436b3abf5eaffbc6907fd68ebedb8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$payload1 = { 31 C9 F7 E1 B0 0B [0-1] 68 2F ?? ?? ?? 68 2F 62 69 6E 89 E3 CD 80 }
		$payload2a = { 31 DB F7 E3 B0 0B 52 }
		$payload2b = { 88 14 1E 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 56 57 53 89 E1 CD 80 }
		$payload3a = { 6A 0B 58 99 52 }
		$payload3b = { 89 E7 68 2F 73 68 00 68 2F 62 69 6E 89 E3 52 E8 }
		$payload3c = { 57 53 89 E1 CD 80 }

	condition:
		$payload1 or ( all of ($payload2*)) or ( all of ($payload3*))
}
