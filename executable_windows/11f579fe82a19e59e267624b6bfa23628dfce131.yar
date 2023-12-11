rule Backdoor_Nitol_Jun17
{
	meta:
		description = "Detects malware backdoor Nitol - file wyawou.exe - Attention: this rule also matches on Upatre Downloader"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/OOB3mH"
		date = "2017-06-04"
		modified = "2023-01-07"
		hash1 = "cba19d228abf31ec8afab7330df3c9da60cd4dae376552b503aea6d7feff9946"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
		$x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
		$x3 = "TCPConnectFloodThread.target = %s" fullword ascii
		$s1 = "\\Program Files\\Internet Explorer\\iexplore.exe" ascii
		$s2 = "%c%c%c%c%c%c.exe" fullword ascii
		$s3 = "GET %s%s HTTP/1.1" fullword ascii
		$s4 = "CCAttack.target = %s" fullword ascii
		$s5 = "Accept-Language: zh-cn" fullword ascii
		$s6 = "jdfwkey" fullword ascii
		$s7 = "hackqz.f3322.org:8880" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or 5 of ($s*))) or ( all of them )
}
