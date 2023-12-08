rule Windows_Trojan_AgentTesla_e577e17e
{
	meta:
		author = "Elastic Security"
		id = "e577e17e-5c42-4431-8c2d-0c1153128226"
		fingerprint = "009cb27295a1aa0dde84d29ee49b8fa2e7a6cec75eccb7534fec3f5c89395a9d"
		creation_date = "2022-03-11"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan AgentTesla variant with fingerprint e577e17e"
		filetype = "executable"

	strings:
		$a = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }

	condition:
		all of them
}
