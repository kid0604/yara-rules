import "pe"

rule APT_CN_Group_Loader_Jan20_1
{
	meta:
		description = "Detects loaders used by Chinese groups"
		author = "Vitali Kremez"
		reference = "https://twitter.com/VK_Intel/status/1223411369367785472?s=20"
		date = "2020-02-01"
		score = 80
		os = "windows"
		filetype = "executable"

	strings:
		$xc1 = { 8B C3 C1 E3 10 C1 E8 10 03 D8 6B DB 77 83 C3 13 }

	condition:
		1 of them
}
