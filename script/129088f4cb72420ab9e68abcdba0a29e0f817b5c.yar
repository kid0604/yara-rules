rule case_23869_anydesk_ps1
{
	meta:
		creation_date = "2024-03-30"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "anydesk install powershell script"
		category = "TOOL"
		malware = "anydesk"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "3064cecf8679d5ba1d981d6990058e1c3fae2846b72fa77acad6ab2b4f582dd7"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "J9kzQ2Y0qO" fullword
		$s2 = "oldadministrator" fullword
		$s3 = "qc69t4B#Z0kE3" fullword
		$s4 = "anydesk.com"

	condition:
		all of them
}
