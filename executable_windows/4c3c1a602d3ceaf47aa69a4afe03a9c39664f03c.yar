import "pe"

rule INDICATOR_KB_CERT_c501b7176b29a3cb737361cf85414874
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0788801185a6bf70b805c2b97a7c6ce66cfbb38d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x8B\\x92\\xE8\\x89\\xBE\\xE8\\xAF\\xB6\\xE8\\x89\\xBE\\xE8\\xB4\\x9D\\xE8\\xAF\\xB6\\xE8\\xAF\\xB6\\xE8\\xB4\\x9D\\xE5\\x90\\xBE\\xE5\\xBC\\x97\\xE5\\xBC\\x97\\xE5\\x90\\xBE\\xE8\\xAF\\xB6\\xE5\\x8B\\x92\\xE8\\xB4\\x9D\\xE5\\xBC\\x97\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE8\\xAF\\xB6\\xE8\\x89\\xBE\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE8\\x89\\xBE\\xE5\\xBC\\x97\\xE5\\xBC\\x97" and pe.signatures[i].serial=="c5:01:b7:17:6b:29:a3:cb:73:73:61:cf:85:41:48:74")
}
