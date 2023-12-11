rule IronPanda_Malware2
{
	meta:
		description = "Iron Panda Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "a89c21dd608c51c4bf0323d640f816e464578510389f9edcf04cd34090decc91"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\setup.exe" ascii
		$s1 = "msi.dll.urlUT" fullword ascii
		$s2 = "msi.dllUT" fullword ascii
		$s3 = "setup.exeUT" fullword ascii
		$s4 = "/c del /q %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <180KB and all of them
}
