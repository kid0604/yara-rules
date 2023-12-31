rule bleedinglife2_adobe_2010_1297_exploit : EK PDF
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "BleedingLife2 Exploit Kit Detection"
		hash0 = "8179a7f91965731daa16722bd95f0fcf"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$string0 = "getSharedStyle"
		$string1 = "currentCount"
		$string2 = "String"
		$string3 = "setSelection"
		$string4 = "BOTTOM"
		$string5 = "classToInstancesDict"
		$string6 = "buttonDown"
		$string7 = "focusRect"
		$string8 = "pill11"
		$string9 = "TEXT_INPUT"
		$string10 = "restrict"
		$string11 = "defaultButtonEnabled"
		$string12 = "copyStylesToChild"
		$string13 = " xmlns:xmpMM"
		$string14 = "_editable"
		$string15 = "classToDefaultStylesDict"
		$string16 = "IMEConversionMode"
		$string17 = "Scene 1"

	condition:
		17 of them
}
