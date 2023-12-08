import "pe"

rule INDICATOR_KB_CERT_0690ee21e99b1cb3b599bba7b9262cdc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ff9a35ef5865024e49096672ab941b5c120657b9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xiamen Tongbu Networks Ltd." and pe.signatures[i].serial=="06:90:ee:21:e9:9b:1c:b3:b5:99:bb:a7:b9:26:2c:dc")
}
