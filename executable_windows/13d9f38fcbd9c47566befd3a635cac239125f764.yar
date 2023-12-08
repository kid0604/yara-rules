import "pe"

rule INDICATOR_KB_CERT_00a3cb8e964244768969b837ca9981de68
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5617114bc2a584532eba1dd9eb9d23108d1f9ea7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="a3:cb:8e:96:42:44:76:89:69:b8:37:ca:99:81:de:68" or pe.signatures[i].serial=="00:a3:cb:8e:96:42:44:76:89:69:b8:37:ca:99:81:de:68")
}
