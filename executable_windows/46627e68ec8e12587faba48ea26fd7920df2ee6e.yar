import "pe"

rule MS17_010_WanaCry_worm
{
	meta:
		description = "Worm exploiting MS17-010 and dropping WannaCry Ransomware"
		author = "Felipe Molina (@felmoltor)"
		reference = "https://www.exploit-db.com/exploits/41987/"
		date = "2017/05/12"
		os = "windows"
		filetype = "executable"

	strings:
		$ms17010_str1 = "PC NETWORK PROGRAM 1.0"
		$ms17010_str2 = "LANMAN1.0"
		$ms17010_str3 = "Windows for Workgroups 3.1a"
		$ms17010_str4 = "__TREEID__PLACEHOLDER__"
		$ms17010_str5 = "__USERID__PLACEHOLDER__"
		$wannacry_payload_substr1 = "h6agLCqPqVyXi2VSQ8O6Yb9ijBX54j"
		$wannacry_payload_substr2 = "h54WfF9cGigWFEx92bzmOd0UOaZlM"
		$wannacry_payload_substr3 = "tpGFEoLOU6+5I78Toh/nHs/RAP"

	condition:
		all of them
}
