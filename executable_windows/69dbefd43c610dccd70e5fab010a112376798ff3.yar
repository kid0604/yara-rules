rule case_23869_sysfunc_dll
{
	meta:
		creation_date = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "Description"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "b3942ead0bf76cf5f4baaa563b603fb6343009c324e3c862d16bbbbdcf482f1a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "gentlemen" fullword
		$s2 = "withdraw fang" fullword
		$s3 = "plants; mould, sympathize, elephant; associate" fullword
		$s4 = "blessing, defender; fashionable" fullword
		$s5 = "withdraw fang" fullword

	condition:
		all of them
}
