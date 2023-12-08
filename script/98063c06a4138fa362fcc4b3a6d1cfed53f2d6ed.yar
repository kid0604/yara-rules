rule CN_Honker_mafix_root
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file root"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "826778ef9c22177d41698b467586604e001fed19"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "echo \"# vbox (voice box) getty\" >> /tmp/.init1" fullword ascii
		$s1 = "cp /var/log/tcp.log $HOMEDIR/.owned/bex2/snifflog" fullword ascii
		$s2 = "if [ -f /sbin/xlogin ]; then" fullword ascii

	condition:
		filesize <96KB and all of them
}
