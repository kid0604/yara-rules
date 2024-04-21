import "pe"

rule cobalt_strike_shellcode_95_dll
{
	meta:
		description = "Cobalt Strike Shellcode"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-06-23"
		os = "windows"
		filetype = "executable"

	strings:
		$str_1 = { E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 }
		$str_2 = "/hVVH"
		$str_3 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENGB)"

	condition:
		3 of them
}
