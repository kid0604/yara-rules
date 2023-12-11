import "pe"

rule INDICATOR_KB_CERT_00ca4822e6905aa4fca9e28523f04f14a3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "35ced9662401f10fa92282e062a8b5588e0c674d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ELISTREID, OOO" and pe.signatures[i].serial=="00:ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3")
}
