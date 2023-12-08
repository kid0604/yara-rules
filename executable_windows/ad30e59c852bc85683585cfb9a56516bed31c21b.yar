import "pe"

rule INDICATOR_KB_CERT_a596fd2779e507aa466d159706fe4150
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "104c4183e248d63a6e2ad6766927b070c81afcb6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ClamAV" and pe.signatures[i].serial=="a5:96:fd:27:79:e5:07:aa:46:6d:15:97:06:fe:41:50")
}
