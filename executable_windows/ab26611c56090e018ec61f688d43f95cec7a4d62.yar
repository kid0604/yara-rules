rule Windows_Trojan_CobaltStrike_5b4383ec
{
	meta:
		author = "Elastic Security"
		id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
		fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Portscan module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "portscan.x64.dll" ascii fullword
		$a2 = "portscan.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\portscan" ascii fullword
		$b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
		$b2 = "(ARP) Target '%s' is alive. " ascii fullword
		$b3 = "TARGETS!12345" ascii fullword
		$b4 = "ReflectiveLoader" ascii fullword
		$b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
		$b6 = "Scanner module is complete" ascii fullword
		$b7 = "pingpong" ascii fullword
		$b8 = "PORTS!12345" ascii fullword
		$b9 = "%s:%d (%s)" ascii fullword
		$b10 = "PREFERENCES!12345" ascii fullword

	condition:
		2 of ($a*) or 6 of ($b*)
}
