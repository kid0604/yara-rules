rule Sofacy_AZZY_Backdoor_Implant_1
{
	meta:
		description = "AZZY Backdoor Implant 4.3 - Sample 1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "1bab1a3e0e501d3c14652ecf60870e483ed4e90e500987c35489f17a44fef26c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\tf394kv.dll" wide
		$s2 = "DWN_DLL_MAIN.dll" fullword ascii
		$s3 = "?SendDataToServer_2@@YGHPAEKEPAPAEPAK@Z" ascii
		$s4 = "?Applicate@@YGHXZ" ascii
		$s5 = "?k@@YGPAUHINSTANCE__@@PBD@Z" ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 2 of them
}
