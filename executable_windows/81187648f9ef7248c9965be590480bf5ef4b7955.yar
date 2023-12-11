import "pe"

rule INDICATOR_KB_CERT_008b3333d32b2c2a1d33b41ba5db9d4d2d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7ecaa9a507a6672144a82d453413591067fc1d27"
		hash1 = "5d5684ccef3ce3b6e92405f73794796e131d3cb1424d757828c3fb62f70f6227"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BOOK CAF\\xC3\\x89" and (pe.signatures[i].serial=="8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d" or pe.signatures[i].serial=="00:8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d"))
}
