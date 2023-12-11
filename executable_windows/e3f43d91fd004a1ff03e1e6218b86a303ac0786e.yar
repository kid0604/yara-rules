import "pe"

rule INDICATOR_KB_CERT_00dadf44e4046372313ee97b8e394c4079
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "80986ae0d4f8c8fabf6c4a91550c90224e26205a4ca61c00ff6736dd94817e65"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Digital Capital Management Ireland Limited" and pe.signatures[i].serial=="00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79")
}
