rule Windows_Trojan_Lokibot_1f885282
{
	meta:
		author = "Elastic Security"
		id = "1f885282-b60e-491e-ae1b-d26825e5aadb"
		fingerprint = "a7519bb0751a6c928af7548eaed2459e0ed26128350262d1278f74f2ad91331b"
		creation_date = "2021-06-22"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Lokibot"
		reference_sample = "916eded682d11cbdf4bc872a8c1bcaae4d4e038ac0f869f59cc0a83867076409"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Lokibot variant 1f885282"
		filetype = "executable"

	strings:
		$a1 = "MAC=%02X%02X%02XINSTALL=%08X%08Xk" fullword

	condition:
		all of them
}
