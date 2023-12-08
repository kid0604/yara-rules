import "pe"

rule INDICATOR_KB_CERT_09e015e98e4fabcc9ac43e042c96090d
{
	meta:
		author = "ditekSHen"
		description = "Detects BestEncrypt commercial disk encryption and wiping software signing certificate"
		thumbprint = "04e407118516053ff248503b31d6eec6daf4a809"
		reference1 = "https://www.virustotal.com/gui/file/859f845ee7c741f34ce8bd53d0fe806eccc2395fc413077605fae3db822094b4/details"
		reference2 = "https://blog.macnica.net/blog/2020/11/dtrack.html"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jetico Inc. Oy" and pe.signatures[i].serial=="09:e0:15:e9:8e:4f:ab:cc:9a:c4:3e:04:2c:96:09:0d")
}
