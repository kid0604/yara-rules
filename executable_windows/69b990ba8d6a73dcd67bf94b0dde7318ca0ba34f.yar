rule Windows_Trojan_CobaltStrike_91e08059
{
	meta:
		author = "Elastic Security"
		id = "91e08059-46a8-47d0-91c9-e86874951a4a"
		fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Post Ex module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "postex.x64.dll" ascii fullword
		$a2 = "postex.dll" ascii fullword
		$a3 = "RunAsAdminCMSTP" ascii fullword
		$a4 = "KerberosTicketPurge" ascii fullword
		$b1 = "GetSystem" ascii fullword
		$b2 = "HelloWorld" ascii fullword
		$b3 = "KerberosTicketUse" ascii fullword
		$b4 = "SpawnAsAdmin" ascii fullword
		$b5 = "RunAsAdmin" ascii fullword
		$b6 = "NetDomain" ascii fullword

	condition:
		2 of ($a*) or 4 of ($b*)
}
