import "pe"

rule INDICATOR_KB_CERT_1deea179f5757fe529043577762419df
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9c4e87ccd6004a70115f8e654b8cc1a80d488876ff2e4e7db598303fa41b3fef"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPIRIT CONSULTING s. r. o." and pe.signatures[i].serial=="1d:ee:a1:79:f5:75:7f:e5:29:04:35:77:76:24:19:df")
}
