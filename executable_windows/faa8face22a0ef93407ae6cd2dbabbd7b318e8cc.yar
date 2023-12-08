import "pe"

rule INDICATOR_KB_CERT_00ab1d5e43e4dde77221381e21a764c082
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b84a817517ed50dbae5439be54248d30bd7a3290"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dadddbffbfcbdaaeeccecbbffac" and pe.signatures[i].serial=="00:ab:1d:5e:43:e4:dd:e7:72:21:38:1e:21:a7:64:c0:82")
}
