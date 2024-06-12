rule Linux_Trojan_Metasploit_f7a31e87
{
	meta:
		author = "Elastic Security"
		id = "f7a31e87-c3d7-4a26-9879-68893780283e"
		fingerprint = "7171cb9989405be295479275d8824ced7e3616097db88e3b0f8f1ef6798607e2"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x86 msfvenom shell find tag payloads"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "82b55d8c0f0175d02399aaf88ad9e92e2e37ef27d52c7f71271f3516ba884847"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$setup = { 31 DB 53 89 E6 6A 40 B7 0A 53 56 53 89 E1 86 FB 66 FF 01 6A 66 58 CD 80 81 3E }
		$payload1 = { 5F FC AD FF }
		$payload2 = { 5F 89 FB 6A 02 59 6A 3F 58 CD 80 49 79 ?? 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80 }

	condition:
		$setup and 1 of ($payload*)
}
