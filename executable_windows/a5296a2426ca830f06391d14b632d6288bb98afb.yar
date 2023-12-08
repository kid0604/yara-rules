import "pe"

rule INDICATOR_KB_CERT_be2f22c152bb218b898c4029056816a9
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "85fe11e799609306516d82e026d4baef4c1e9ad3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Marts GmbH" and (pe.signatures[i].serial=="be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9" or pe.signatures[i].serial=="00:be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9"))
}
