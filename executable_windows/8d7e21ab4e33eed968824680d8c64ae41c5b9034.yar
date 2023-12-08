import "pe"

rule INDICATOR_KB_CERT_00ce40906451925405d0f6c130db461f71
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "af79bbdb4fa0724f907343e9b1945ffffb34e9b3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xD0\\xA5\\xE7\\xBB\\xB4\\xE6\\x9D\\xB0\\xE6\\x96\\xAF\\xE6\\x96\\xAF\\xE7\\xBB\\xB4\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xD0\\xA5\\xE6\\x96\\xAF\\xD0\\xA5\\xD0\\xA5\\xE6\\x96\\xAF\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE6\\x96\\xAF\\xE6\\x9D\\xB0" and pe.signatures[i].serial=="00:ce:40:90:64:51:92:54:05:d0:f6:c1:30:db:46:1f:71")
}
