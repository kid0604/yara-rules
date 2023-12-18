import "pe"

rule INDICATOR_KB_CERT_df2547b2cab5689a81d61de80eaaa3a2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4c6e21a6e96ea6fae6c142c2d1c919f590d9bf4e5c6b0f3ec7f9b0a38f3ce45d"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORWARD MUSIC AGENCY SRL" and pe.signatures[i].serial=="df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2")
}
