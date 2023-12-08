import "pe"

rule INDICATOR_KB_CERT_58ec8821aa2a3755e1075f73321756f4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "19dd0d7f2edf32ea285577e00dd13c966844cfa4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cbebbfeaddcbcccffdcdc" and pe.signatures[i].serial=="58:ec:88:21:aa:2a:37:55:e1:07:5f:73:32:17:56:f4")
}
