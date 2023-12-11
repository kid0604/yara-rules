import "pe"

rule EXT_MAL_SystemBC_Mar22_1
{
	meta:
		author = "Thomas Barabosch, Deutsche Telekom Security"
		date = "2022-03-11"
		description = "Detects unpacked SystemBC module as used by Emotet in March 2022"
		score = 85
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.systembc"
		reference = "https://twitter.com/Cryptolaemus1/status/1502069552246575105"
		reference2 = "https://medium.com/walmartglobaltech/inside-the-systembc-malware-as-a-service-9aa03afd09c6"
		hash1 = "c926338972be5bdfdd89574f3dc2fe4d4f70fd4e24c1c6ac5d2439c7fcc50db5"
		os = "windows"
		filetype = "executable"

	strings:
		$sx1 = "-WindowStyle Hidden -ep bypass -file" ascii
		$sx2 = "BEGINDATA" ascii
		$sx3 = "GET %s HTTP/1.0" ascii
		$s5 = "User-Agent:" ascii
		$s8 = "ALLUSERSPROFILE" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and 2 of ($sx*)) or all of them
}
