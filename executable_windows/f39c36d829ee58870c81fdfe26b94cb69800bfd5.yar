import "pe"

rule INDICATOR_KB_CERT_00a73b6d821f84db4451d6eedd62c42848
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "eca61ad880741629967004bfc40bf8df6c9f0794"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mht Holding Vinderup ApS" and pe.signatures[i].serial=="00:a7:3b:6d:82:1f:84:db:44:51:d6:ee:dd:62:c4:28:48")
}
