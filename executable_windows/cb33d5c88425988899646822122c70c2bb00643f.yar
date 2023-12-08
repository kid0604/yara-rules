rule APT_Malware_PutterPanda_Gen4
{
	meta:
		description = "Detects Malware related to PutterPanda"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "71a8378fa8e06bcf8ee9f019c807c6bfc58dca0c"
		hash1 = "8fdd6e5ed9d69d560b6fdd5910f80e0914893552"
		hash2 = "3c4a762175326b37035a9192a981f7f4cc2aa5f0"
		hash3 = "598430b3a9b5576f03cc4aed6dc2cd8a43324e1e"
		hash4 = "6522b81b38747f4aa09c98fdaedaed4b00b21689"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "rz.dat" fullword ascii
		$s0 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii
		$s1 = "Internet connect error:%d" fullword ascii
		$s2 = "Proxy-Authorization:Basic " fullword ascii
		$s5 = "Invalid url" fullword ascii
		$s6 = "Create file failed" fullword ascii
		$s7 = "myAgent" fullword ascii
		$z1 = "%s%s%d%d" fullword ascii
		$z2 = "HttpQueryInfo failed:%d" fullword ascii
		$z3 = "read file error:%d" fullword ascii
		$z4 = "down file success" fullword ascii
		$z5 = "kPStoreCreateInstance" fullword ascii
		$z6 = "Avaliable data:%u bytes" fullword ascii
		$z7 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" fullword ascii

	condition:
		filesize <300KB and (( uint16(0)==0x5a4d and $x1 and 3 of ($s*)) or (3 of ($s*) and 4 of ($z*)))
}
