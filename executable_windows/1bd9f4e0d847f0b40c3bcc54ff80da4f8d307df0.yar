import "pe"

rule INDICATOR_KB_CERT_00d59a05955a4a421500f9561ce983aac4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7f56555ac8479d4e130a89e787b7ff2f47005cc02776cf7a30a58611748c4c2e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Olymp LLC" and pe.signatures[i].serial=="00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4")
}
