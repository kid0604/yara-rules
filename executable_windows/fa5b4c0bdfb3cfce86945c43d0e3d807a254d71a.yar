import "pe"

rule INDICATOR_KB_CERT_4d26bab89fcf7ff9fa4dc4847e563563
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2be34a7a39df38f66d5550dcfa01850c8f165c81"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "qvarn pty ltd" and pe.signatures[i].serial=="4d:26:ba:b8:9f:cf:7f:f9:fa:4d:c4:84:7e:56:35:63")
}
