import "pe"

rule CoinMiner_imphash
{
	meta:
		description = "Detects the risk of CoinMiner Trojan rule 3"
		os = "windows"
		filetype = "executable"

	condition:
		pe.imphash()=="563557d99523e4b1f8aab2eb9b79285e"
}
