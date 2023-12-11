import "pe"

rule ZxShell_Related_Malware_CN_Group_Jul17_2
{
	meta:
		description = "Detects a ZxShell related sample from a CN threat group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/cat-phishing/"
		date = "2017-07-08"
		hash1 = "204273675526649b7243ee48efbb7e2bc05239f7f9015fbc4fb65f0ada64759e"
		os = "windows"
		filetype = "executable"

	strings:
		$u1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
		$u2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
		$u3 = "User-Agent:Mozilla/5.0 (X11; U; Linux i686; en-US; re:1.4.0) Gecko/20080808 Firefox/%d.0" fullword ascii
		$u4 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
		$x1 = "\\\\%s\\admin$\\g1fd.exe" fullword ascii
		$x2 = "C:\\g1fd.exe" fullword ascii
		$x3 = "\\\\%s\\C$\\NewArean.exe" fullword ascii
		$s0 = "at \\\\%s %d:%d %s" fullword ascii
		$s1 = "%c%c%c%c%ccn.exe" fullword ascii
		$s2 = "hra%u.dll" fullword ascii
		$s3 = "Referer: http://%s:80/http://%s" fullword ascii
		$s5 = "Accept-Language: zh-cn" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 3 of them )
}
