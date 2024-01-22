rule CrybtBot_Stealer
{
	meta:
		description = "This Role Detects unpacked version of CryptBot Stealer, you can use it for memory scan."
		Data = "21/1/2024"
		Author = "@FarghlyMal"
		sha265 = "381333799197CDF21B4D12D9CE83587673C52B336547A5425BBD9C69BBA00D5F"
		sample = "https://bazaar.abuse.ch/sample/381333799197cdf21b4d12d9ce83587673c52b336547a5425bbd9c69bba00d5f/"
		os = "windows"
		filetype = "executable"

	strings:
		$hex_s1 = {99 BE (66|C9) 00 00 00 F7 FE}
		$S1 = "unic16m.top" wide ascii
		$S10 = "unic16e.top" wide ascii
		$S2 = "%wS\\formhistory.sqlite" wide ascii
		$S3 = "%wS\\Mozilla\\Firefox\\%wS" wide ascii
		$S4 = "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000" wide ascii
		$S5 = "\\files_\\screenshot.jp" wide ascii
		$S6 = "(chrome default)" wide ascii
		$S7 = "(chrome profile 1)" wide ascii
		$S8 = "%ComSpec%" wide ascii
		$S9 = "UserName (ComputerName): %wS" wide ascii

	condition:
		7 of ($S*) and #hex_s1>=1
}
