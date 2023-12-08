import "pe"

rule INDICATOR_KB_CERT_eb95a7bd7553533d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8d658fd671fa097c3db18906a29e8c1fa45113d9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\x02C\\x02\\x97\\x04\\x17\\x04\\x1e\\x04.\\x02\\x90\\x00g\\x02\\x94\\x02\\xae\\x00p\\x04 \\x00K\\x04J\\x02\\x88\\x042\\x02K\\x02\\xa3" and pe.signatures[i].serial=="eb:95:a7:bd:75:53:53:3d")
}
