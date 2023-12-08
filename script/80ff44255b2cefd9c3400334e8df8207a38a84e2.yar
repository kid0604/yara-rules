rule XMRIG_Monero_Miner_Config
{
	meta:
		description = "Auto-generated rule - from files config.json, config.json"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/xmrig/xmrig/releases"
		date = "2018-01-04"
		hash1 = "031333d44a3a917f9654d7e7257e00c9d961ada3bee707de94b7c7d06234909a"
		hash2 = "409b6ec82c3bdac724dae702e20cb7f80ca1e79efa4ff91212960525af016c41"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s2 = "\"cpu-affinity\": null,   // set process affinity to CPU core(s), mask \"0x3\" for cores 0 and 1" fullword ascii
		$s5 = "\"nicehash\": false                  // enable nicehash/xmrig-proxy support" fullword ascii
		$s8 = "\"algo\": \"cryptonight\",  // cryptonight (default) or cryptonight-lite" fullword ascii

	condition:
		( uint16(0)==0x0a7b or uint16(0)==0x0d7b) and filesize <5KB and 1 of them
}
