import "pe"

rule sig_17333_module
{
	meta:
		description = "17333 - file module.ahk"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
		date = "2023-02-03"
		hash1 = "e4b2411286d32e6c6d3d7abffc70d296c814e837ef14f096c829bf07edd45180"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "; by Lexikos - https://autohotkey.com/board/topic/110808-getkeyname-for-other-languages/#entry682236" fullword ascii
		$s2 = ";This code works with a getkeyname from a Dllcall (See Bottom Script- by Lexikos)" fullword ascii
		$s3 = "; ChangeLog : v2.22 (2017-02-25) - Now pressing the same combination keys continuously more than 2 times," fullword ascii
		$s4 = ": DllCall(\"GetWindowThreadProcessId\", \"ptr\", WinExist(WinTitle), \"ptr\", 0)" fullword ascii
		$s5 = "RegWrite, REG_SZ, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue,%outvar%" fullword ascii
		$s6 = "RegRead, outvar, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue" fullword ascii
		$s7 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_GETDEFAULTINPUTLANG, \"UInt\", 0, \"UintP\", binaryLocaleID, \"UInt\", 0)" fullword ascii
		$s8 = "hkl := DllCall(\"GetKeyboardLayout\", \"uint\", thread, \"ptr\")" fullword ascii
		$s9 = ";KeypressValueToREG.ahk comes from KeypressOSD.ahk that was Created by Author RaptorX" fullword ascii
		$s10 = "Hotkey, % \"~*Numpad\" A_Index - 1, OnKeyPressed" fullword ascii
		$s11 = "RegWrite, REG_SZ, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue," fullword ascii
		$s12 = "RegWrite, REG_DWORD, HKEY_CURRENT_USER,software\\GetKeypressValue,InputLocaleID,%InputLocaleID%" fullword ascii
		$s13 = "Hotkey, % \"~*Numpad\" A_Index - 1 \" Up\", _OnKeyUp" fullword ascii
		$s14 = "; Open this Script in Wordpad and For Changelog look to the Bottom of the script. " fullword ascii
		$s15 = "RegRead, InputLocaleID, HKEY_CURRENT_USER,software\\GetKeypressValue,InputLocaleID" fullword ascii
		$s16 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_SETDEFAULTINPUTLANG, \"UInt\", 0, \"UPtr\", &binaryLocaleID, \"UInt\", SPIF_SEND" ascii
		$s17 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_SETDEFAULTINPUTLANG, \"UInt\", 0, \"UPtr\", &binaryLocaleID, \"UInt\", SPIF_SEND" ascii
		$s18 = ";             v2.20 (2017-02-24) - Added displaying continuous-pressed combination keys." fullword ascii
		$s19 = "PostMessage 0x50, 0, % Lan, , % \"ahk_id \" windows%A_Index%" fullword ascii
		$s20 = ";             v2.01 (2016-09-11) - Display non english keyboard layout characters when combine with modifer keys." fullword ascii

	condition:
		uint16(0)==0x4b3b and filesize <30KB and all of them
}
