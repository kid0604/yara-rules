import "pe"

rule Greenbug_Malware_4
{
	meta:
		description = "Detects ISMDoor Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		super_rule = 1
		hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
		hash2 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "powershell.exe -nologo -windowstyle hidden -c \"Set-ExecutionPolicy -scope currentuser" fullword ascii
		$s2 = "powershell.exe -c \"Set-ExecutionPolicy -scope currentuser -ExecutionPolicy unrestricted -f; . \"" fullword ascii
		$s3 = "c:\\windows\\temp\\tmp8873" fullword ascii
		$s4 = "taskkill /im winit.exe /f" fullword ascii
		$s5 = "invoke-psuacme"
		$s6 = "-method oobe -payload \"\"" fullword ascii
		$s7 = "C:\\ProgramData\\stat2.dat" fullword wide
		$s8 = "Invoke-bypassuac" fullword ascii
		$s9 = "Start Keylog Done" fullword wide
		$s10 = "Microsoft\\Windows\\WinIt.exe" fullword ascii
		$s11 = "Microsoft\\Windows\\Tmp9932u1.bat\"" fullword ascii
		$s12 = "Microsoft\\Windows\\tmp43hh11.txt" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them ) or (3 of them )
}
