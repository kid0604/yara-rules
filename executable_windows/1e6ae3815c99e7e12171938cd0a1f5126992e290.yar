rule FourElementSword_Config_File
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "01,,hccutils.dll,2" fullword ascii
		$s1 = "RegisterDlls=OurDll" fullword ascii
		$s2 = "[OurDll]" fullword ascii
		$s3 = "[DefaultInstall]" fullword ascii
		$s4 = "Signature=\"$Windows NT$\"" fullword ascii

	condition:
		4 of them
}
