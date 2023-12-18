import "pe"

rule INDICATOR_KB_CERT_43bb437d609866286dd839e1d00309f5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "21c13d0a5037ebb97eb9ae094d8d5839b4bc9bba751c848064c82ec3a42a3134"
		reason = "QuasarRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NVIDIA Corporation" and pe.signatures[i].serial=="43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5")
}
