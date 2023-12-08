import "pe"

rule INDICATOR_KB_CERT_e414655f025399cca4d7225d89689a04
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "98643cef3dc22d0cc730be710c5a30ae25d226c1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\xAF\\x94\\xE5\\x90\\xBE\\xE8\\xBF\\xAA\\xE5\\x90\\xBE\\xE8\\xBF\\xAA\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE8\\xBF\\xAA\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE6\\x8F\\x90\\xE4\\xBC\\x8A\\xE6\\xAF\\x94\\xE6\\x8F\\x90\\xE8\\xBF\\xAA\\xE8\\xBF\\xAA\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE6\\x8F\\x90\\xE7\\xBB\\xB4\\xE6\\xAF\\x94" and pe.signatures[i].serial=="e4:14:65:5f:02:53:99:cc:a4:d7:22:5d:89:68:9a:04")
}
