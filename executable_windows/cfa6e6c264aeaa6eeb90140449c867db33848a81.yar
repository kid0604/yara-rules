import "pe"

rule INDICATOR_KB_CERT_371381a66fb96a07077860ae4a6721e1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "c4419f095ae93d93e145d678ed31459506423d6a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE7\\xBB\\xB4\\xD0\\xA9\\xE5\\x90\\xBE\\xE7\\xBB\\xB4\\xD0\\xA9\\xD0\\xA9\\xE7\\xBB\\xB4\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xD0\\xA9\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xD0\\xA9\\xE5\\xA8\\x9C\\xE6\\x9D\\xB0\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xE5\\xA8\\x9C\\xE5\\xA8\\x9C\\xD0\\xA9" and pe.signatures[i].serial=="37:13:81:a6:6f:b9:6a:07:07:78:60:ae:4a:67:21:e1")
}
