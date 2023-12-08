rule CN_Honker_safe3wvs_cgiscan
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cgiscan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f94bbf2034ad9afa43cca3e3a20f142e0bb54d75"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "httpclient.exe" fullword wide
		$s3 = "www.safe3.com.cn" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <357KB and all of them
}
