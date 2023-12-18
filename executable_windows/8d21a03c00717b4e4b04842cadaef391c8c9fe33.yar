import "pe"

rule INDICATOR_KB_CERT_59f296d0af649e0962d724248d9fdcdb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ce2aa31a714cc05f86d726a959f6655efc40777aa474fb6b9689154fdc918a44"
		reason = "DarkGate"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MK ZN s.r.o." and pe.signatures[i].serial=="59:f2:96:d0:af:64:9e:09:62:d7:24:24:8d:9f:dc:db")
}
