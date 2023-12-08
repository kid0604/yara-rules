import "hash"

rule setup_moneroocean_miner : bash mining xmrig
{
	meta:
		description = "Detect the risk of CoinMiner Monero Rule 3"
		os = "linux"
		filetype = "script"

	strings:
		$ = "MoneroOcean mining setup script"
		$ = "setup_moneroocean_miner.sh <wallet address>"
		$ = "TOTAL_CACHE=$(( $CPU_THREADS*$CPU_L1_CACHE + $CPU_SOCKETS"
		$ = "$HOME/moneroocean/xmrig"
		$ = "$LATEST_XMRIG_LINUX_RELEASE"
		$ = "moneroocean_miner.service"

	condition:
		any of them or hash.md5(0, filesize )=="75363103bb838ca8e975d318977c06eb"
}
