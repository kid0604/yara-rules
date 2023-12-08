import "pe"

rule APT17_Malware_Oct17_Gen
{
	meta:
		description = "Detects APT17 malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/puVc9q"
		date = "2017-10-03"
		hash1 = "0375b4216334c85a4b29441a3d37e61d7797c2e1cb94b14cf6292449fb25c7b2"
		hash2 = "07f93e49c7015b68e2542fc591ad2b4a1bc01349f79d48db67c53938ad4b525d"
		hash3 = "ee362a8161bd442073775363bf5fa1305abac2ce39b903d63df0d7121ba60550"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" fullword ascii
		$x2 = "http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus&tbnid=aLW4-J8Q1lmYBM" ascii
		$s1 = "hWritePipe2 Error:%d" fullword ascii
		$s2 = "Not Support This Function!" fullword ascii
		$s3 = "Cookie: SESSIONID=%s" fullword ascii
		$s4 = "http://0.0.0.0/1" fullword ascii
		$s5 = "Content-Type: image/x-png" fullword ascii
		$s6 = "Accept-Language: en-US" fullword ascii
		$s7 = "IISCMD Error:%d" fullword ascii
		$s8 = "[IISEND=0x%08X][Recv:] 0x%08X %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="414bbd566b700ea021cfae3ad8f4d9b9" or 1 of ($x*) or 6 of them ))
}
