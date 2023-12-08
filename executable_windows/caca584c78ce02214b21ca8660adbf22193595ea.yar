import "pe"

rule INDICATOR_KB_CERT_09b3a7e559fcb024c4b66b794e9540cb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "59c60ade491c9eda994711b1fdb59510baad2ea3"
		hash1 = "b57d694b6d1f9e0634953e8f5c1e4faf84fb50be806a8887dd5b31bfd58a167f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Windscribe Limited" and pe.signatures[i].serial=="09:b3:a7:e5:59:fc:b0:24:c4:b6:6b:79:4e:95:40:cb")
}
