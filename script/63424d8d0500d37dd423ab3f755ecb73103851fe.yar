import "pe"

rule Solarmarker_Dropper
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "Based on import hash and string observations with March 2022 solarmarker dropper"
		reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html"
		os = "windows"
		filetype = "script"

	strings:
		$htt1 = "PowerShell"
		$htt2 = "System.Collections.ObjectModel"
		$htt3 = "System.Management.Automation"
		$htt4 = ".NETFramework"
		$htt5 = "HashAlgorithm"

	condition:
		pe.imphash()=="b8bb385806b89680e13fc0cf24f4431e" and 3 of ($htt*)
}
