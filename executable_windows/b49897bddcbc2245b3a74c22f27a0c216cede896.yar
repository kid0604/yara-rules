import "pe"

rule INDICATOR_KB_CERT_67144b9ed89fb2d106d0233873c6e35f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5971faead4c86bf72e6ab36efc0376d4abfffeda"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Infosignal LLC" and pe.signatures[i].serial=="67:14:4b:9e:d8:9f:b2:d1:06:d0:23:38:73:c6:e3:5f")
}
