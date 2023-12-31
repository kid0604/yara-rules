rule ccleaner_backdoor_alt_1
{
	meta:
		description = "Ccleaner 5.33 backdoor with a possible APT17/Group72 connection."
		reference = "http://blog.talosintelligence.com/2017/09/ccleaner-c2-concern.html"
		author = "@fusionrace"
		md5_1 = "d488e4b61c233293bec2ee09553d3a2f"
		md5_2 = "b95911a69e49544f9ecc427478eb952f"
		md5_3 = "063b58879c8197b06d619c3be90506ec"
		md5_4 = "7690e414e130acf7c962774c05283142"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "s:\\workspace\\ccleaner\\branches\\v5.33" fullword ascii wide

	condition:
		$s1
}
