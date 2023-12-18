import "pe"

rule INDICATOR_KB_CERT_65cfd8419d70ce4011d97bc79d18315e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7cff10e37a43843e971f02ca6ad6510f08a5209d21745181fc4d003a8287cd1b"
		reason = "BumbleBee"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FACE AESTHETICS LTD" and pe.signatures[i].serial=="65:cf:d8:41:9d:70:ce:40:11:d9:7b:c7:9d:18:31:5e")
}
