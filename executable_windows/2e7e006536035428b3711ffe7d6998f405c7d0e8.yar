import "pe"

rule INDICATOR_KB_CERT_f44a91704f9ea388446d2635f2a8c8a5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "573514c39bcef5690ab924f9df30577def6e877f"
		hash1 = "d67dde5621d6de76562bc2812f04f986b441601b088aa936d821c0504eb4f7aa"
		hash2 = "71f60a985d2cc9fc47c6845a88eea4da19303a96a2ff69daae70276f70dcdae0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Binance" and pe.signatures[i].serial=="f4:4a:91:70:4f:9e:a3:88:44:6d:26:35:f2:a8:c8:a5")
}
