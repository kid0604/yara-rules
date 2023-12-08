import "pe"

rule APT17_Malware_Oct17_2
{
	meta:
		description = "Detects APT17 malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/puVc9q"
		date = "2017-10-03"
		hash1 = "20cd49fd0f244944a8f5ba1d7656af3026e67d170133c1b3546c8b2de38d4f27"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Cookie: __xsptplus=%s" fullword ascii
		$x2 = "http://services.fiveemotions.co.jp" fullword ascii
		$x3 = "http://%s/ja-JP/2015/%d/%d/%d%d%d%d%d%d%d%d.gif" fullword ascii
		$s1 = "FoxHTTPClient_EXE_x86.exe" fullword ascii
		$s2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.3072" ascii
		$s3 = "hWritePipe2 Error:%d" fullword ascii
		$s4 = "Not Support This Function!" fullword ascii
		$s5 = "Global\\PnP_No_Management" fullword ascii
		$s6 = "Content-Type: image/x-png" fullword ascii
		$s7 = "Accept-Language: ja-JP" fullword ascii
		$s8 = "IISCMD Error:%d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (pe.exports("_foo@0") or 1 of ($x*) or 6 of them )
}
