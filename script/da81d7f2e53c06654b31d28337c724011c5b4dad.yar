rule CoinHive_Javascript_MoneroMiner : HIGHVOL
{
	meta:
		description = "Detects CoinHive - JavaScript Crypto Miner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		reference = "https://coinhive.com/documentation/miner"
		date = "2018-01-04"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii

	condition:
		filesize <65KB and 1 of them
}
