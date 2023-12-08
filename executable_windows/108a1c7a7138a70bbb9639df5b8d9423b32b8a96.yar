import "pe"

rule CoinMiner01
{
	meta:
		description = "Detects the risk of CoinMiner Trojan rule 1"
		detail = "Detects coinminer payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "-o pool." ascii wide
		$s2 = "--cpu-max-threads-hint" ascii wide
		$s3 = "-P stratum" ascii wide
		$s4 = "--farm-retries" ascii wide
		$dl = "github.com/ethereum-mining/ethminer/releases/download" ascii wide

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) or ($dl))
}
