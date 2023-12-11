import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_NoneWindowsUA
{
	meta:
		author = "ditekSHen"
		description = "Detects Windows executables referencing non-Windows User-Agents"
		os = "windows"
		filetype = "executable"

	strings:
		$ua1 = "Mozilla/5.0 (Macintosh; Intel Mac OS" wide ascii
		$ua2 = "Mozilla/5.0 (iPhone; CPU iPhone OS" ascii wide
		$ua3 = "Mozilla/5.0 (Linux; Android " ascii wide
		$ua4 = "Mozilla/5.0 (PlayStation " ascii wide
		$ua5 = "Mozilla/5.0 (X11; " wide ascii
		$ua6 = "Mozilla/5.0 (Windows Phone " ascii wide
		$ua7 = "Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)" wide ascii
		$ua8 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)" wide ascii
		$ua9 = "HTC_Touch_3G Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 7.11)" wide ascii
		$ua10 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows Phone OS 7.0; Trident/3.1; IEMobile/7.0; Nokia;N70)" wide ascii
		$ua11 = "Mozilla/5.0 (BlackBerry; U; BlackBerry " wide ascii
		$ua12 = "Mozilla/5.0 (iPad; CPU OS" wide ascii
		$ua13 = "Mozilla/5.0 (iPad; U;" ascii wide
		$ua14 = "Mozilla/5.0 (IE 11.0;" ascii wide
		$ua15 = "Mozilla/5.0 (Android;" ascii wide
		$ua16 = "User-Agent: Internal Wordpress RPC connection" ascii wide
		$ua17 = "Mozilla / 5.0 (SymbianOS" ascii wide

	condition:
		uint16(0)==0x5a4d and 1 of them
}
