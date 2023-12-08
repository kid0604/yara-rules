import "pe"

rule INDICATOR_KB_CERT_00bbd4dc3768a51aa2b3059c1bad569276
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "36936c4aa401c3bbeb227ce5011ec3bdc02fdd14"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JJ ELECTRICAL SERVICES LIMITED" and pe.signatures[i].serial=="00:bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76")
}
