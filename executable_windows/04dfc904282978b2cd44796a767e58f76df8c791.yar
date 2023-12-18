import "pe"

rule INDICATOR_KB_CERT_029bf7e1cb09fe277564bd27c267de5a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2b18684a4b1348bf78f6d58d3397ee5ca80610d1c39b243c844e08f1c1e0b4bf"
		reason = "Lazarus"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAMOYAJ LIMITED" and pe.signatures[i].serial=="02:9b:f7:e1:cb:09:fe:27:75:64:bd:27:c2:67:de:5a")
}
