import "hash"

rule uninstall_moneroocean_miner : bash mining xmrig
{
	meta:
		description = "Detect the risk of CoinMiner Monero Rule 4"
		os = "linux"
		filetype = "script"

	strings:
		$default1 = "moneroocean"
		$default2 = "mining uninstall script"
		$s1 = "sudo systemctl stop"
		$s2 = "sudo systemctl disable"
		$s3 = "rm -f /etc/systemd/system/"
		$s4 = "sudo systemctl daemon-reload"

	condition:
		($default1 or $default2) and any of ($s*) or hash.md5(0, filesize )=="b059718f365d30a559afacf2d86bc379"
}
