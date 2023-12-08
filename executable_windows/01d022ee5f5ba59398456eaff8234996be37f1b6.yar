import "pe"

rule INDICATOR_KB_CERT_008fe807310d98357a59382090634b93f0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "acd6cf38d03c355ddb84b96a7365bfc1738a0ec5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MAVE MEDIA" and pe.signatures[i].serial=="00:8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0")
}
