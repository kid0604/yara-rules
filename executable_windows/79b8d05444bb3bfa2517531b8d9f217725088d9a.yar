import "pe"

rule INDICATOR_KB_CERT_becd4ef55ced54e5bcde595d872ae7eb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "72ae9b9a32b4c16b5a94e2b4587bc51a91b27052"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dedbfdefcac" and pe.signatures[i].serial=="be:cd:4e:f5:5c:ed:54:e5:bc:de:59:5d:87:2a:e7:eb")
}
