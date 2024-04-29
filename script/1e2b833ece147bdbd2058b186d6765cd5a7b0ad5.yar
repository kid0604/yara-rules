rule case_23869_sysfunc_cmd
{
	meta:
		creation_date = "2024-03-29"
		first_imported = "2024-03-29"
		last_modified = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "File generated dynamically from awscollector.ps1"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "f3b211c45090f371869c396716972429896e0427da55ce8f1981787c2ea7eb0b"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "@echo off" fullword
		$s2 = "DEL \"%~f0\"" fullword
		$s3 = "bcedit /set {default] bootstatuspolicy ignorereallifefailures" fullword
		$s4 = "bcedit /set {default] recoveryenabled no" fullword
		$s5 = "vssadmin delete shadows /all /quiet" fullword
		$s6 = "wmic shadowcopy /nointeractive" fullword
		$s7 = "wmic shadowcopy delete" fullword

	condition:
		all of them
}
