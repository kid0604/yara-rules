import "pe"

rule INDICATOR_KB_CERT_105765998695197de4109828a68a4ee0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5ddae14820d6f189e637f90b81c4fdb78b5419dc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cryptonic ApS" and pe.signatures[i].serial=="10:57:65:99:86:95:19:7d:e4:10:98:28:a6:8a:4e:e0")
}
