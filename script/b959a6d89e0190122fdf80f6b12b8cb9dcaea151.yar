rule SUSP_LNX_SH_CryptoMiner_Indicators_Dec20_1
{
	meta:
		description = "Detects helper script used in a crypto miner campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
		date = "2020-12-31"
		hash1 = "3298dbd985c341d57e3219e80839ec5028585d0b0a737c994363443f4439d7a5"
		os = "linux"
		filetype = "script"

	strings:
		$x1 = "miner running" fullword ascii
		$x2 = "miner runing" fullword ascii
		$x3 = " --donate-level 1 "
		$x4 = " -o pool.minexmr.com:5555 " ascii

	condition:
		filesize <20KB and 1 of them
}
