import "pe"

rule INDICATOR_KB_CERT_54cc50d147fa549e3f721c754e4e3a91
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e3143f0df21fced02fe5525b297ed4cd389c66e3"
		hash1 = "85adf569d259dc53c5099fea6e90ff3a614a406b4308ebdf9f40e8bed151f526"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ralink Technology Corporation" and pe.signatures[i].serial=="54:cc:50:d1:47:fa:54:9e:3f:72:1c:75:4e:4e:3a:91")
}
