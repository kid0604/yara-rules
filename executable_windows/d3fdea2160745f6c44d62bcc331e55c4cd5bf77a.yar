import "pe"

rule INDICATOR_KB_CERT_6d450cc59acdb4b7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "bd3ac678cabb6465854880dd06b7b6cd231def89"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CancellationTokenSource" and pe.signatures[i].serial=="6d:45:0c:c5:9a:cd:b4:b7")
}
