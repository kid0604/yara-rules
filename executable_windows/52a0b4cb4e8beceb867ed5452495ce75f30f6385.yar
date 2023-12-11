import "pe"

rule INDICATOR_KB_CERT_59a57e8ba3dcf2b6f59981fda14b03
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e201821e152d7ae86078c4e6a3a3a1e1c5e29f9a"
		hash1 = "d9ace2d97010316fdb0f416920232e8d4c59b01614633c4d5def79abb15d0175"
		hash2 = "80e363dee08f4f77e5a061c10f18503c7ce802818cf6bb1c8a16da0ba3877b01"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Medium LLC" and pe.signatures[i].serial=="59:a5:7e:8b:a3:dc:f2:b6:f5:99:81:fd:a1:4b:03")
}
