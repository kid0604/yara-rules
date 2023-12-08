rule EquationGroup_envisioncollision
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file envisioncollision"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "75d5ec573afaf8064f5d516ae61fd105012cbeaaaa09c8c193c7b4f9c0646ea1"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "mysql \\$D --host=\\$H --user=\\$U --password=\\\"\\$P\\\" -e \\\"select * from \\$T" fullword ascii
		$x2 = "Window 3: $0 -Uadmin -Ppassword -i127.0.0.1 -Dipboard -c\\\"sleep 500|nc" fullword ascii
		$s3 = "$ua->agent(\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\");" fullword ascii
		$s4 = "$url = $host . \"/admin/index.php?adsess=\" . $enter . \"&app=core&module=applications&section=hooks&do=install_hook\";" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <20KB and 1 of ($x*)) or (2 of them )
}
