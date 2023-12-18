import "pe"

rule INDICATOR_KB_CERT_e573d9c8b403c41bd59ffa0a8efd4168
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a9ab2be0ea677c6c6ed67b23cfee0fa44bfb346a4bb720f10a3f02a78b8f5c82"
		reason = "Dridex"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VERONIKA 2\" OOO\"" and pe.signatures[i].serial=="e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68")
}
