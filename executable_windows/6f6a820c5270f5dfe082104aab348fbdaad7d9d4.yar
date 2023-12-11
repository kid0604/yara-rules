import "pe"

rule INDICATOR_KB_CERT_4929ab561c812af93ddb9758b545f546
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0946bf998f8a463a1c167637537f3eba35205b748efc444a2e7f935dc8dd6dc7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Everything Wow s.r.o." and pe.signatures[i].serial=="49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46")
}
