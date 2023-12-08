import "pe"

rule INDICATOR_KB_CERT_0b5759bc22ad2128b8792e8535f9161e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ddfd6a93a8d33f0797d5fdfdb9abf2b66e64350a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ceeacfeacafdcdffabdbbacf" and pe.signatures[i].serial=="0b:57:59:bc:22:ad:21:28:b8:79:2e:85:35:f9:16:1e")
}
