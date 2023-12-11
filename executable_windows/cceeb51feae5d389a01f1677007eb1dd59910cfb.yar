rule BlackEnergy_Driver_USBMDM
{
	meta:
		description = "Black Energy Driver"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
		date = "2016-01-04"
		super_rule = 1
		hash1 = "7874a10e551377d50264da5906dc07ec31b173dee18867f88ea556ad70d8f094"
		hash2 = "b73777469f939c331cbc1c9ad703f973d55851f3ad09282ab5b3546befa5b54a"
		hash3 = "edb16d3ccd50fc8f0f77d0875bf50a629fa38e5ba1b8eeefd54468df97eba281"
		hash4 = "ac13b819379855af80ea3499e7fb645f1c96a4a6709792613917df4276c583fc"
		hash5 = "7a393b3eadfc8938cbecf84ca630e56e37d8b3d23e084a12ea5a7955642db291"
		hash6 = "405013e66b6f137f915738e5623228f36c74e362873310c5f2634ca2fda6fbc5"
		hash7 = "244dd8018177ea5a92c70a7be94334fa457c1aab8a1c1ea51580d7da500c3ad5"
		hash8 = "edcd1722fdc2c924382903b7e4580f9b77603110e497393c9947d45d311234bf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "USB MDM Driver" fullword wide
		$s2 = "KdDebuggerNotPresent" fullword ascii
		$s3 = "KdDebuggerEnabled" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <180KB and all of them
}
