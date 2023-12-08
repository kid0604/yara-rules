rule MAL_DNSPIONAGE_Malware_Nov18
{
	meta:
		description = "Detects DNSpionage Malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html"
		date = "2018-11-30"
		modified = "2023-01-06"
		hash1 = "2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec"
		hash2 = "45a9edb24d4174592c69d9d37a534a518fbe2a88d3817fc0cc739e455883b8ff"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = ".0ffice36o.com" ascii
		$s1 = "/Client/Login?id=" ascii
		$s2 = ".\\Configure.txt" ascii
		$s5 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii
		$s6 = "Content-Disposition: form-data; name=\"txts\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (1 of ($x*) or 2 of them )
}
