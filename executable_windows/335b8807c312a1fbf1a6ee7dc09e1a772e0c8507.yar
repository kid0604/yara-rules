rule apt_hiddencobra_binaries
{
	meta:
		description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure"
		author = "US-CERT"
		url = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = "Wating" wide ascii
		$STR2 = "Reamin" wide ascii
		$STR3 = "laptos" wide ascii

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and 2 of them
}
