import "pe"

rule INDICATOR_KB_CERT_3533080b377f80c0ea826b2492bf767b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "2afcc4cdee842d80bf7b6406fb503957c8a09b4d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\xA8\\x9C\\xE8\\xBF\\xAA\\xD0\\x91\\xE8\\xBF\\xAA\\xD0\\x91\\xE5\\xA8\\x9C\\xE5\\x93\\xA6\\xE5\\xB0\\xBA\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xD0\\x91\\xE8\\xBF\\xAA\\xD0\\x91\\xE5\\xB0\\xBA\\xE5\\xB0\\xBA\\xE8\\xBF\\xAA\\xE5\\x93\\xA6\\xE8\\xBF\\xAA\\xE5\\x8B\\x92\\xD0\\x91\\xE5\\x8B\\x92\\xE5\\x93\\xA6\\xE5\\x8B\\x92\\xE5\\x93\\xA6\\xD0\\x91" and pe.signatures[i].serial=="35:33:08:0b:37:7f:80:c0:ea:82:6b:24:92:bf:76:7b")
}
