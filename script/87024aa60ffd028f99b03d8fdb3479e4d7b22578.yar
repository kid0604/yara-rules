rule case_23869_awscollector_ps1
{
	meta:
		creation_date = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "awscollector.ps1"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "e737831bea7ab9e294bf6b58ca193ba302b8869f5405aa6d3a6492d0334a04a6"
		os = "windows"
		filetype = "script"

	strings:
		$author = "darussian@tutanota.com" fullword
		$s1 = "Locker" fullword
		$s2 = "Find-Remote-Executor" fullword
		$s3 = "lockerparams" fullword
		$s4 = "locker_cmd_list" fullword
		$s5 = "AWSCLIV2" fullword

	condition:
		$author or ( all of ($s*))
}
