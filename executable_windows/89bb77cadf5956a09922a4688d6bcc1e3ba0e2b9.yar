import "pe"

rule INDICATOR_KB_CERT_90212473c706f523fe84bdb9a78a01f4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6b18e9451c2e93564ed255e754b7e1cf0f817abda93015b21ae5e247c75f9d03"
		reason = "Cerber"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DEMUS, OOO" and pe.signatures[i].serial=="90:21:24:73:c7:06:f5:23:fe:84:bd:b9:a7:8a:01:f4")
}
