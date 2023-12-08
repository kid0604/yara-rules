import "pe"

rule INDICATOR_KB_CERT_64f82ed8a90f92a940be2bb90fbf6f48
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4d00f5112caf80615852ffe1f4ee72277ed781c3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Klimate Vision Plus" and pe.signatures[i].serial=="64:f8:2e:d8:a9:0f:92:a9:40:be:2b:b9:0f:bf:6f:48")
}
