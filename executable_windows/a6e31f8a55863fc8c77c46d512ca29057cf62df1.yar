import "pe"

rule INDICATOR_KB_CERT_8cece6df54cf6ad63596546d77ba3581
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1a9ff8aba1b24e3bd06442ac6d593ff224b685cba4edef79e740f569ab453161"
		reason = "Malware"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mikael LLC" and pe.signatures[i].serial=="8c:ec:e6:df:54:cf:6a:d6:35:96:54:6d:77:ba:35:81")
}
