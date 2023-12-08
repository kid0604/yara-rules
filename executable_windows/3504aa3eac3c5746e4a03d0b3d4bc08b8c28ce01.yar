import "pe"

rule INDICATOR_KB_CERT_294e7a2ccfc28ed02843ecff25f2ac98
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a57a2de9b04a80e9290df865c0abd3b467318144"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eadbaadbdcecafdfafbe" and pe.signatures[i].serial=="29:4e:7a:2c:cf:c2:8e:d0:28:43:ec:ff:25:f2:ac:98")
}
