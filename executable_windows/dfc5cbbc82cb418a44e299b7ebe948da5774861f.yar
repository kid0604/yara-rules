rule kiwi_tools_gentil_kiwi
{
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash8 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash9 = "febadc01a64a071816eac61a85418711debaf233"
		hash10 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash11 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash12 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash13 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash14 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash15 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mimikatz" fullword wide
		$s2 = "Copyright (C) 2012 Gentil Kiwi" fullword wide
		$s3 = "Gentil Kiwi" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
