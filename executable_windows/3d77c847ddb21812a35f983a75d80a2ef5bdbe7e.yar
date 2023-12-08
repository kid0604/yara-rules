import "pe"

rule INDICATOR_KB_CERT_21e3cae5b77c41528658ada08509c392
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8acfaa12e5d02c1e0daf0a373b0490d782ea5220"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Network Design International Holdings Limited" and pe.signatures[i].serial=="21:e3:ca:e5:b7:7c:41:52:86:58:ad:a0:85:09:c3:92")
}
