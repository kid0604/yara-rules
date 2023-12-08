import "pe"

rule INDICATOR_KB_CERT_1e74cfe7de8c5f57840a61034414ca9f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "2dfa711a12aed0ace72e538c57136fa021412f95951c319dcb331a3e529cf86e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Insta Software Solution Inc." and pe.signatures[i].serial=="1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f")
}
