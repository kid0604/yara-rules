rule Windows_Trojan_CobaltStrike_6e77233e
{
	meta:
		author = "Elastic Security"
		id = "6e77233e-7fb4-4295-823d-f97786c5d9c4"
		fingerprint = "cef2949eae78b1c321c2ec4010749a5ac0551d680bd5eb85493fc88c5227d285"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Kerberos module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
		$a2 = "$unwind$command_kerberos_ticket_use" ascii fullword
		$a3 = "$pdata$command_kerberos_ticket_use" ascii fullword
		$a4 = "command_kerberos_ticket_use" ascii fullword
		$a5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
		$a6 = "command_kerberos_ticket_purge" ascii fullword
		$a7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
		$a8 = "$unwind$kerberos_init" ascii fullword
		$a9 = "$unwind$KerberosTicketUse" ascii fullword
		$a10 = "KerberosTicketUse" ascii fullword
		$a11 = "$unwind$KerberosTicketPurge" ascii fullword
		$b1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
		$b2 = "_command_kerberos_ticket_use" ascii fullword
		$b3 = "_command_kerberos_ticket_purge" ascii fullword
		$b4 = "_kerberos_init" ascii fullword
		$b5 = "_KerberosTicketUse" ascii fullword
		$b6 = "_KerberosTicketPurge" ascii fullword
		$b7 = "_LsaCallKerberosPackage" ascii fullword

	condition:
		5 of ($a*) or 3 of ($b*)
}
