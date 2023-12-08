import "pe"

rule INDICATOR_KB_CERT_00c1afabdaa1321f815cdbb9467728bc08
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "e9c5fb9a7d3aba4b49c41b45249ed20c870f5c9e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xD0\\x92\\xD0\\x93\\xE5\\x84\\xBF\\xD0\\x93\\xE5\\x8B\\x92\\xD0\\x92\\xE5\\x8B\\x92\\xD0\\x93\\xD0\\x93\\xE5\\x84\\xBF\\xE8\\x89\\xBE\\xD0\\x92\\xD0\\x93\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xD0\\x92\\xD0\\x93\\xE8\\x89\\xBE\\xE9\\xA9\\xAC\\xD0\\x93\\xE8\\x89\\xBE\\xE9\\xA9\\xAC\\xD0\\x93" and pe.signatures[i].serial=="00:c1:af:ab:da:a1:32:1f:81:5c:db:b9:46:77:28:bc:08")
}
