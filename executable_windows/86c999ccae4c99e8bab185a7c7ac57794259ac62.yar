rule APT_Malware_PutterPanda_Rel_2
{
	meta:
		description = "APT Malware related to PutterPanda Group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "f97e01ee04970d1fc4d988a9e9f0f223ef2a6381"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "http://update.konamidata.com/test/zl/sophos/td/result/rz.dat?" fullword ascii
		$s1 = "http://update.konamidata.com/test/zl/sophos/td/index.dat?" fullword ascii
		$s2 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii
		$s3 = "Internet connect error:%d" fullword ascii
		$s4 = "Proxy-Authorization:Basic" fullword ascii
		$s5 = "HttpQueryInfo failed:%d" fullword ascii
		$s6 = "read file error:%d" fullword ascii
		$s7 = "downdll.dll" fullword ascii
		$s8 = "rz.dat" fullword ascii
		$s9 = "Invalid url" fullword ascii
		$s10 = "Create file failed" fullword ascii
		$s11 = "myAgent" fullword ascii
		$s12 = "%s%s%d%d" fullword ascii
		$s13 = "down file success" fullword ascii
		$s15 = "error!" fullword ascii
		$s18 = "Avaliable data:%u bytes" fullword ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
