import "pe"

rule INDICATOR_KB_CERT_bd1e93d5787a737eef930c70986d2a69
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "921e5d7f9f05272b566533393d7194ea9227e582"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cdefedddbdedbcbfffbeadb" and pe.signatures[i].serial=="bd:1e:93:d5:78:7a:73:7e:ef:93:0c:70:98:6d:2a:69")
}
