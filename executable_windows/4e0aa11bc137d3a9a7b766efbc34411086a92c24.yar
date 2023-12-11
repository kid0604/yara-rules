rule PassCV_Sabre_Malware_2
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "475d1c2d36b2cf28b28b202ada78168e7482a98b42ff980bbb2f65c6483db5b4"
		hash2 = "009645c628e719fad2e280ef60bbd8e49bf057196ac09b3f70065f1ad2df9b78"
		hash3 = "92479c7503393fc4b8dd7c5cd1d3479a182abca3cda21943279c68a8eef9c64b"
		hash4 = "0c7b952c64db7add5b8b50b1199fc7d82e9b6ac07193d9ec30e5b8d353b1f6d2"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "ncProxyXll" fullword ascii
		$s1 = "Uniscribe.dll" fullword ascii
		$s2 = "WS2_32.dll" ascii
		$s3 = "ProxyDll" fullword ascii
		$s4 = "JDNSAPI.dll" fullword ascii
		$s5 = "x64.dat" fullword ascii
		$s6 = "LSpyb2" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and $x1) or ( all of them )
}
