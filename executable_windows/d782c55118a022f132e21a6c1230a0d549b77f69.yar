import "pe"

rule INDICATOR_KB_CERT_0889e4181e71b16c4a810bee38a78419
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "bce3c17815ec9f720ba9c59126ae239c9caf856d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x8B\\x92\\xE5\\xBC\\x97\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE5\\x90\\xBE\\xE4\\xBC\\x8A\\xE5\\x90\\xBE" and pe.signatures[i].serial=="08:89:e4:18:1e:71:b1:6c:4a:81:0b:ee:38:a7:84:19")
}
