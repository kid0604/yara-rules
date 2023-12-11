import "pe"

rule INDICATOR_KB_CERT_2304ecf0ea2b2736beddd26a903ba952
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d59a63e230cef77951cb73a8d65576f00c049f44"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\x88\\x90\\xE9\\x83\\xBD\\xE5\\x90\\x89\\xE8\\x83\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE8\\xB4\\xA3\\xE4\\xBB\\xBB\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="23:04:ec:f0:ea:2b:27:36:be:dd:d2:6a:90:3b:a9:52")
}
