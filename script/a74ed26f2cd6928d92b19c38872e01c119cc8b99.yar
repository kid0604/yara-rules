rule APT_RU_Sandworm_PY_May20_1
{
	meta:
		description = "Detects Sandworm Python loader"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/billyleonard/status/1266054881225236482"
		date = "2020-05-28"
		hash1 = "c025008463fdbf44b2f845f2d82702805d931771aea4b506573b83c8f58bccca"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "o.addheaders=[('User-Agent','Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko')]" ascii fullword
		$s1 = "exec(o.open('http://" ascii
		$s2 = "__import__({2:'urllib2',3:'urllib.request'}"

	condition:
		uint16(0)==0x6d69 and filesize <1KB and 1 of ($x*) or 2 of them
}
