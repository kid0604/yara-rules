import "pe"

rule INDICATOR_KB_CERT_967cb0898680d1c174b2baae5fa332db
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c231f1e6cc3aec983d892e1bc3bb1815335fb24e3e2f611d79bade9a07cbd819"
		reason = "Babadeda"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "James Caulfield" and pe.signatures[i].serial=="96:7c:b0:89:86:80:d1:c1:74:b2:ba:ae:5f:a3:32:db")
}
