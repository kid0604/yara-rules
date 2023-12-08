import "pe"

rule INDICATOR_KB_CERT_b0009bb062f52eb6001ba79606de243d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c89f06937d24b7f13be5edba5e0e2f4e05bc9b13"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fbfdddcfabc" and pe.signatures[i].serial=="b0:00:9b:b0:62:f5:2e:b6:00:1b:a7:96:06:de:24:3d")
}
