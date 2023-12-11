import "hash"

rule XmrigConfig : json mining xmrig
{
	meta:
		description = "Detect the risk of CoinMiner givemexyz Rule 9"
		detail = "xmrig config.json"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "\"worker-id\":" ascii
		$ = "\"randomx\":" ascii
		$ = "\"donate-level\":" ascii
		$ = "\"rig-id\":" ascii
		$ = "\"donate-over-proxy\":" ascii

	condition:
		3 of them
}
