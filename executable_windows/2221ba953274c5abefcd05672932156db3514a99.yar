rule VirtualPC_Detection : AntiVM
{
	meta:
		description = "Looks for VirtualPC presence"
		author = "Cuckoo project"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = {0F 3F 07 0B }
		$virtualpc1 = "vpcbus" nocase wide ascii
		$virtualpc2 = "vpc-s3" nocase wide ascii
		$virtualpc3 = "vpcuhub" nocase wide ascii
		$virtualpc4 = "msvmmouf" nocase wide ascii

	condition:
		any of them
}
