rule IronPanda_Malware4
{
	meta:
		description = "Iron Panda Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "0d6da946026154416f49df2283252d01ecfb0c41c27ef3bc79029483adc2240c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "TestPlugin.dll" fullword wide
		$s1 = "<a href='http://www.baidu.com'>aasd</a>" fullword wide
		$s2 = "Zcg.Test.AspxSpyPlugins" fullword ascii
		$s6 = "TestPlugin" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <10KB and all of them
}
