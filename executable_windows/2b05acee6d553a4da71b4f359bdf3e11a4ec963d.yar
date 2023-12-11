rule IronPanda_Malware3
{
	meta:
		description = "Iron Panda Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "5cd2af844e718570ae7ba9773a9075738c0b3b75c65909437c43201ce596a742"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "PluginDeflater.exe" fullword wide
		$s1 = ".Deflated" fullword wide
		$s2 = "PluginDeflater" fullword ascii
		$s3 = "DeflateStream" fullword ascii
		$s4 = "CompressionMode" fullword ascii
		$s5 = "System.IO.Compression" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <10KB and all of them
}
