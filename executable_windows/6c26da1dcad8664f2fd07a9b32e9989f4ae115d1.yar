import "pe"

rule INDICATOR_KB_CERT_0537f25a88e24cafdd7919fa301e8146
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "922211f5ab4521941d26915aeb82ee728f931082"
		hash = "72ac61e6311f2a6430d005052dbc0cc58587e7b75722b5e34a71081370f4ddd5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Avira Operations GmbH & Co. KG" and pe.signatures[i].serial=="05:37:f2:5a:88:e2:4c:af:dd:79:19:fa:30:1e:81:46")
}
