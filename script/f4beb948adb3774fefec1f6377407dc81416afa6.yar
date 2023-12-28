rule CryptHunter_pythonSimpleRAT
{
	meta:
		description = "2nd stage python simple rat in Dangerouspassword"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "39bbc16028fd46bf4ddad49c21439504d3f6f42cccbd30945a2d2fdb4ce393a4"
		hash2 = "5fe1790667ee5085e73b054566d548eb4473c20cf962368dd53ba776e9642272"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$domain01 = "www.git-hub.me" ascii wide fullword
		$domain02 = "nivyga.com" ascii wide fullword
		$domain03 = "tracking.nivyga.com" ascii wide fullword
		$domain04 = "yukunmaoyi.com" ascii wide fullword
		$domain05 = "gameofwarsite.com" ascii wide fullword
		$domain06 = "togetherwatch.com" ascii wide fullword
		$domain07 = "9d90-081d2f-vultr-los-angeles-boxul.teridions.net" ascii wide fullword
		$domain08 = "8dae-77766a-vultr-los-angeles-egnyte-sj.d1.teridioncloud.net" ascii wide fullword
		$domain09 = "www.jacarandas.top" ascii wide fullword
		$domain10 = "cleargadgetwinners.top" ascii wide fullword
		$domain11 = "ns1.smoothieking.info" ascii wide fullword
		$domain12 = "ns2.smoothieking.info" ascii wide fullword
		$str01 = "Jvaqbjf" ascii wide fullword
		$str02 = "Yvahk" ascii wide fullword
		$str03 = "Qnejva" ascii wide fullword
		$str04 = "GITHUB_REQ" ascii wide fullword
		$str05 = "GITHUB_RES" ascii wide fullword
		$str06 = "BasicInfo" ascii wide fullword
		$str07 = "CmdExec" ascii wide fullword
		$str08 = "DownExec" ascii wide fullword
		$str09 = "KillSelf" ascii wide fullword
		$str10 = "pp -b /gzc/.VPR-havk/tvg" ascii wide fullword
		$str11 = "/gzc/.VPR-havk/tvg" ascii wide fullword
		$str12 = "NccyrNppbhag.gtm" ascii wide fullword
		$str13 = "/GrzcHfre/NccyrNppbhagNffvfgnag.ncc" ascii wide fullword
		$str14 = "Pheerag Gvzr" ascii wide fullword
		$str15 = "Hfreanzr" ascii wide fullword
		$str16 = "Ubfganzr" ascii wide fullword
		$str17 = "BF Irefvba" ascii wide fullword
		$str18 = "VQ_YVXR=qrovna" ascii wide fullword
		$str19 = "VQ=qrovna" ascii wide fullword
		$str20 = "/rgp/bf-eryrnfr" ascii wide fullword
		$str21 = " -yafy -ycguernq -yerfbyi -fgq=tah99" ascii wide fullword

	condition:
		( filesize >1KB) and ( filesize <5MB) and (1 of ($domain*) or (5 of ($str*)))
}
