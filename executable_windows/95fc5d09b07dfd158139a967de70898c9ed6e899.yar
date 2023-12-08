import "pe"

rule MALWARE_Win_Milan
{
	meta:
		author = "ditekSHen"
		description = "Detects Milan Lyceum backdoor"
		hash1 = "21ab4357262993a042c28c1cdb52b2dab7195a6c30fa8be723631604dd330b29"
		hash2 = "a2754d7995426b58317e437f8ed6770cd7bb7b18d971e23b2b300b75e34fa086"
		hash3 = "b46949feeda8726c0fb86d3cd32d3f3f53f6d2e6e3fcd6f893a76b8b2632b249"
		hash4 = "b54a67062bdcd32dfa9f3d7b69780d2e6e4925777290bc34e8f979a1b4b72ea2"
		hash5 = "b766522dd4189fef7775d663e5649ba9d8be8e03022039d20848fcbc3643e5f2"
		hash6 = "d3606e2e36db0a0cb1b8168423188ee66332cae24fe59d63f93f5f53ab7c3029"
		hash7 = "857e2f63a1078d49adc59a03482f7b362563f16fb251f174bdaa7759ed47922a"
		hash8 = "4f1b8c9209fa2684aa3777353222ad1c7716910dbb615d96ffc7882eb81dd248"
		os = "windows"
		filetype = "executable"

	strings:
		$ua1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 4.0; .NET CLR 2.0.50727)" fullword wide
		$ua2 = "Mozilla/5.0 (Android; Mobile; rv:28.0) Gecko/28.0 Firefox/28.0" fullword wide
		$ua3 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 520)" fullword wide
		$ua4 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; XBLWP7; ZuneWP7)" fullword wide
		$ua5 = "Mozilla/5.0 (IE 11.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C; rv:11.0) like Gecko" fullword wide
		$ua6 = "Mozilla/5.0 (iPad; U; CPU OS 5_1_1 like Mac OS X; en-us) AppleWebKit/534.46.0 (KHTML, like Gecko) CriOS/19.0.1084.60 Mobile/9B206 Safari/7534.48.3" fullword wide
		$ua7 = "Mozilla/5.0 (Linux; Android 4.1; Galaxy Nexus Build/JRN84D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19" fullword wide
		$ua8 = "Mozilla/5.0 (Linux; Android 7.1.1; ASUS_X017DA Build/NGI77B; rv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Rocket/1.5.1(11790) Chrome/74.0.3729.157 Mobile Safari/537.36" fullword wide
		$ua9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword wide
		$ua10 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36" fullword wide
		$ua11 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36" fullword wide
		$ua12 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0" fullword wide
		$n1 = "charset={[A-Za-z0-9\\-_]+}" fullword wide
		$n2 = "Content-Length: {[0-9]+}" fullword wide
		$n3 = "Location: {[0-9]+}" fullword wide
		$n4 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
		$n5 = "{<html>}" fullword wide
		$n6 = "&formid=" fullword ascii
		$n7 = "/?id=" fullword ascii
		$p1 = "\\milan\\Debug\\Milan.pdb" ascii
		$p2 = "\\milan\\Release\\Milan.pdb" ascii
		$p3 = "\\BackDor Last\\" ascii
		$p4 = "\\BackDorLast\\" ascii
		$s1 = "/q \"%s\" & waitfor" wide
		$s2 = "/q \"%s\" & schtasks /delete" wide
		$s3 = "*BOT@;" fullword ascii
		$s4 = "mofcomp \"" fullword ascii
		$s5 = "\"WQL\";};instance of " ascii
		$s6 = "</svalue>" fullword wide
		$s7 = "cmd.exe /C " wide nocase
		$d1 = "akastatus.com" ascii
		$d2 = "centosupdatecdn.com" ascii
		$d3 = "checkinternet.org" ascii
		$d4 = "cybersecnet.co.za" ascii
		$d5 = "cybersecnet.org" ascii
		$d6 = "defenderlive.com" ascii
		$d7 = "defenderstatus.com" ascii
		$d8 = "digitalmarketingagency.net" ascii
		$d9 = "dnsanalizer.com" ascii
		$d10 = "dnscatalog.net" ascii
		$d11 = "dnscdn.org" ascii
		$d12 = "dnsstatus.org" ascii
		$d13 = "excsrvcdn.com" ascii
		$d14 = "hpesystem.com" ascii
		$d15 = "livednscdn.com" ascii
		$d16 = "micrsoftonline.net" ascii
		$d17 = "ndianmombais.com" ascii
		$d18 = "online-analytic.com" ascii
		$d19 = "securednsservice.net" ascii
		$d20 = "sysadminnews.info" ascii
		$d21 = "uctpostgraduate.com" ascii
		$d22 = "updatecdn.net" ascii
		$d23 = "web-traffic.info" ascii
		$d24 = "windowsupdatecdn.com" ascii
		$d25 = "wsuslink.com" ascii
		$d26 = "zonestatistic.com" ascii

	condition:
		uint16(0)==0x5a4d and ((1 of ($p*) and (2 of ($s*) or 2 of ($ua*))) or (5 of ($n*) and (2 of ($ua*) or 1 of ($p*) or 1 of ($s*))) or (3 of ($s*) and (2 of ($ua*) or 5 of ($n*))) or (2 of ($d*) and 6 of them ))
}
