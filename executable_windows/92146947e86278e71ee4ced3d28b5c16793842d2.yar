import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_CC_Regex
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing credit card regular expressions"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "^3[47][0-9]{13}$" ascii wide nocase
		$s2 = "3[47][0-9]{13}$" ascii wide nocase
		$s3 = "37[0-9]{2}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
		$s4 = "^(6541|6556)[0-9]{12}$" ascii wide nocase
		$s5 = "^389[0-9]{11}$" ascii wide nocase
		$s6 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" ascii wide nocase
		$s7 = "6(?:011|5[0-9]{2})[0-9]{12}$" ascii wide nocase
		$s8 = "6011\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
		$s9 = "^63[7-9][0-9]{13}$" ascii wide nocase
		$s10 = "^(?:2131|1800|35\\d{3})\\d{11}$" ascii wide nocase
		$s11 = "^9[0-9]{15}$" ascii wide nocase
		$s12 = "^(6304|6706|6709|6771)[0-9]{12,15}$" ascii wide nocase
		$s13 = "^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" ascii wide nocase
		$s14 = "5[1-5][0-9]{14}$" ascii wide nocase
		$s15 = "^(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}$" ascii wide nocase
		$s16 = "^(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}$" ascii wide nocase
		$s17 = "^(62[0-9]{14,17})$" ascii wide nocase
		$s18 = "4[0-9]{12}(?:[0-9]{3})?$" ascii wide nocase
		$s19 = "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" ascii wide nocase
		$s20 = "4[0-9]{3}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
		$a21 = "^[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase

	condition:
		( uint16(0)==0x5a4d and 2 of them ) or (4 of them )
}
