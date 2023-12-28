import "elf"

rule malware_GobRATLoader
{
	meta:
		description = "GobRAT Loader ShellScript"
		author = "JPCERT/CC Incident Response Group"
		hash = "3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1"
		os = "linux"
		filetype = "script"

	strings:
		$str1 = "CACHEDEV3_DATA CACHEDEV2_DATA CACHEDEV1_DATA MD0_DATA"
		$str2 = "#clean old program cache"
		$str3 = "firewalld stop error"
		$str4 = "firewalld disable  error"
		$str5 = "CPU architecture: 8"
		$str6 = "#download elf with rate 200k"
		$str7 = "#kill old elf process"
		$str8 = "#normal daemon to hold backdoor running"
		$str9 = "#autorun own, insert to qnap autorun script"
		$str10 = "# insert ssh public backdoor"
		$str11 = "Pi5papdFA0M9z6AQoa9Y31ww65f8P5slNf1Q8vloVIwg"
		$str12 = "#set a daemon script"
		$str13 = "#autorun 2 "
		$str14 = "grep frpc |grep -v grep | awk"
		$str15 = "iptables error"

	condition:
		( filesize <15KB) and (3 of ($str*))
}
