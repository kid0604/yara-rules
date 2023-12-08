rule Windows_Trojan_AgentTesla_f2a90d14
{
	meta:
		author = "Elastic Security"
		id = "f2a90d14-7212-41a5-a2cd-a6a6dedce96e"
		fingerprint = "829c827069846ba1e1378aba8ee6cdc801631d769dc3dce15ccaacd4068a88a6"
		creation_date = "2022-03-11"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan AgentTesla with fingerprint f2a90d14"
		filetype = "executable"

	strings:
		$a = { 0B FE 01 2C 0B 07 16 7E 08 00 00 04 A2 1F 0C 0C 00 08 1F 09 FE 01 }

	condition:
		all of them
}
