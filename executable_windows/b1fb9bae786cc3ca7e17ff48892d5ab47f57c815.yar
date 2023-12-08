import "pe"

rule INDICATOR_KB_CERT_00c865d49345f1ed9a84bea40743cdf1d7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "d5e8afa85c6bf68d31af4a04668c3391e48b24b7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\xB0\\x94\\xE5\\x93\\xA6\\xD0\\x93\\xE8\\x89\\xBE\\xE5\\xB1\\x81\\xE5\\xB1\\x81\\xE5\\x93\\xA6\\xE5\\xB1\\x81\\xE5\\x93\\xA6\\xE7\\xBB\\xB4\\xE5\\x93\\xA6\\xE8\\x89\\xBE\\xE5\\xB0\\x94\\xE8\\x89\\xBE" and pe.signatures[i].serial=="00:c8:65:d4:93:45:f1:ed:9a:84:be:a4:07:43:cd:f1:d7")
}
