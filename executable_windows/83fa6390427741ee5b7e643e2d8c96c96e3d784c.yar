import "pe"

rule INDICATOR_KB_CERT_24e4a2b3db6be1007b9ddc91995bc0c8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "005af6c8e9f06a2258c2df70785a5622c8d10d982fdc7f4dbe2f53af6e860359"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FLY BETTER s.r.o." and pe.signatures[i].serial=="24:e4:a2:b3:db:6b:e1:00:7b:9d:dc:91:99:5b:c0:c8")
}
