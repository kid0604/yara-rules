import "pe"

rule INDICATOR_KB_CERT_603bce30597089d068320fc77e400d06
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4ddda7e006afb108417627f8f22a6fa416e3f264"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fcaddefffedacfc" and pe.signatures[i].serial=="60:3b:ce:30:59:70:89:d0:68:32:0f:c7:7e:40:0d:06")
}
