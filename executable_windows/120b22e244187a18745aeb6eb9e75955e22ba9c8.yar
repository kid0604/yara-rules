import "pe"

rule INDICATOR_KB_CERT_0fd7f9cac1e9ce71ac757f93266e3b13
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "af2779ceb127caa6c22232ad359888a0a71ce221"
		hash1 = "7c28b994aeb3a85e37225cc20bae2232f97e23f115c2a409da31f353140c631e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE9\\x9D\\x92\\xE5\\xB2\\x9B\\xE4\\xB8\\x89\\xE5\\x96\\x9C\\xE8\\xB4\\xB8\\xE6\\x98\\x93\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="0f:d7:f9:ca:c1:e9:ce:71:ac:75:7f:93:26:6e:3b:13")
}
