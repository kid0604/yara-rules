import "pe"

rule INDICATOR_KB_CERT_016836311fc39fbb8e6f308bb03cc2b3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "cab373e2d4672beacf4ca9c9baf75a2182a106cca5ea32f2fc2295848771a979"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SERVICE STREAM LIMITED" and pe.signatures[i].serial=="01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3")
}
