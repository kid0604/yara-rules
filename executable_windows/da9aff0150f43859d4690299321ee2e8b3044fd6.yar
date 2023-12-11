import "pe"

rule INDICATOR_KB_CERT_0084817e07288a5025b9435570e7fec1d3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f22e8c59b7769e4a9ade54aee8aaf8404a7feaa7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE8\\xB4\\xBC\\xE8\\x89\\xBE\\xE5\\xBE\\xB7\\xE8\\xB4\\xBC\\xE6\\x8F\\x90\\xD0\\xAD\\xD0\\xAD\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE8\\xB4\\xBC\\xD0\\xAD\\xE5\\xBE\\xB7\\xE8\\xB4\\xBC\\xE8\\xB4\\xBC\\xE5\\xB0\\x94\\xE6\\x8F\\x90\\xE8\\x89\\xBE\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE5\\xB0\\x94\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE8\\x89\\xBE\\xD0\\xAD\\xE8\\x89\\xBE" and pe.signatures[i].serial=="00:84:81:7e:07:28:8a:50:25:b9:43:55:70:e7:fe:c1:d3")
}
