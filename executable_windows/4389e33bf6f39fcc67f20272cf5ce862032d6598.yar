rule Solarmarker_Packer_Strings
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "Observed ASCII and Wide strings of obfuscated solarmarker dll"
		reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$wstring1 = "zkabsr" wide
		$astring1 = "keyPath" ascii
		$astring2 = "hSection" ascii
		$astring3 = "valueName" ascii
		$astring4 = "StaticArrayInitTypeSize" ascii
		$astring5 = "KeyValuePair" ascii

	condition:
		$mz at 0 and $wstring1 and 1 of ($astring*)
}
