rule Windows_Trojan_CobaltStrike_72f68375
{
	meta:
		author = "Elastic Security"
		id = "72f68375-35ab-49cc-905d-15302389a236"
		fingerprint = "ecc28f414b2c347722b681589da8529c6f3af0491845453874f8fd87c2ae86d7"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Netdomain module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x86.o" ascii fullword
		$b1 = "__imp_BeaconPrintf" ascii fullword
		$b2 = "__imp_NETAPI32$NetApiBufferFree" ascii fullword
		$b3 = "__imp_NETAPI32$DsGetDcNameA" ascii fullword
		$c1 = "__imp__BeaconPrintf" ascii fullword
		$c2 = "__imp__NETAPI32$NetApiBufferFree" ascii fullword
		$c3 = "__imp__NETAPI32$DsGetDcNameA" ascii fullword

	condition:
		1 of ($a*) or 2 of ($b*) or 2 of ($c*)
}
