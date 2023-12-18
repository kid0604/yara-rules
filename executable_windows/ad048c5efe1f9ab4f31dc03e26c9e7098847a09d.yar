import "pe"

rule INDICATOR_KB_CERT_0a2787fbb4627c91611573e323584113
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8badf05b1814d40fb7055283a69a0bc328943100fe12b629f1c14b9448163aac"
		reason = "Malware"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "exxon.com" and pe.signatures[i].serial=="0a:27:87:fb:b4:62:7c:91:61:15:73:e3:23:58:41:13")
}
