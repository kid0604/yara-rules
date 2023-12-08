rule PassCV_Sabre_Malware_1
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "24a9bfbff81615a42e42755711c8d04f359f3bf815fb338022edca860ff1908a"
		hash2 = "e61e56b8f2666b9e605127b4fcc7dc23871c1ae25aa0a4ea23b48c9de35d5f55"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "F:\\Excalibur\\Excalibur\\Excalibur\\" ascii
		$x2 = "bin\\oSaberSvc.pdb" ascii
		$s1 = "cmd.exe /c MD " fullword ascii
		$s2 = "https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=0&rsv_idx=1&tn=baidu&wd=ip138" fullword wide
		$s3 = "CloudRun.exe" fullword wide
		$s4 = "SaberSvcB.exe" fullword wide
		$s5 = "SaberSvc.exe" fullword wide
		$s6 = "SaberSvcW.exe" fullword wide
		$s7 = "tianshiyed@iaomaomark1#23mark123tokenmarkqwebjiuga664115" fullword wide
		$s8 = "Internet Connect Failed!" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and (1 of ($x*) and 5 of ($s*))) or ( all of them )
}
