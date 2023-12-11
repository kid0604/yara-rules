import "pe"

rule INDICATOR_KB_CERT_00b0ecd32f95f8761b8a6d5710c7f34590
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "2e25e7e8abc238b05de5e2a482e51ed324fbaa76"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\x96\\xAF\\xD0\\xA8\\xD0\\xA8\\xE5\\xBC\\x97\\xE6\\xAF\\x94\\xE5\\xBC\\x97\\xD0\\xA8\\xE6\\xAF\\x94\\xD0\\xA8\\xE5\\xBC\\x97\\xD0\\xA8\\xE5\\xB0\\x94\\xE5\\xBC\\x97\\xE5\\xBC\\x97\\xD0\\xA8\\xE5\\xB0\\x94\\xD0\\xA8\\xE6\\x96\\xAF\\xE5\\xB0\\x94\\xE5\\xBC\\x97" and pe.signatures[i].serial=="00:b0:ec:d3:2f:95:f8:76:1b:8a:6d:57:10:c7:f3:45:90")
}
