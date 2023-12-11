import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_TooManyWindowsUA
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing many varying, potentially fake Windows User-Agents"
		os = "windows"
		filetype = "executable"

	strings:
		$ua1 = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36" ascii wide
		$ua2 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36" ascii wide
		$ua3 = "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0" ascii wide
		$ua4 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0" ascii wide
		$ua5 = "Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3" ascii wide
		$ua6 = "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US)" ascii wide
		$ua7 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" ascii wide
		$ua8 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)" ascii wide
		$ua9 = "Opera/12.0(Windows NT 5.2;U;en)Presto/22.9.168 Version/12.00" ascii wide
		$ua10 = "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14" ascii wide
		$ua11 = "Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0 Opera 12.14" ascii wide
		$ua12 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14" ascii wide
		$ua13 = "Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02" ascii wide
		$ua14 = "Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00" ascii wide
		$ua15 = "Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00" ascii wide
		$ua16 = "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7" ascii wide
		$ua17 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27" ascii wide

	condition:
		uint16(0)==0x5a4d and 5 of them
}
