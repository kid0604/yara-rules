import "pe"

rule MALWARE_Win_PowerPool_STG2
{
	meta:
		author = "ditekSHen"
		description = "Detects second stage PowerPool backdoor"
		snort2_sid = "920089-920091"
		snort3_sid = "920087-920089"
		clamav_sig = "MALWARE.Win.Trojan.PowerPool-STG-2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "write info fail!!! GetLastError-->%u" fullword ascii
		$s2 = "LookupAccountSid Error %u" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; )" fullword ascii
		$s4 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SE)" fullword ascii
		$s5 = "Content-Disposition: form-data; name=\"%s\"" fullword ascii
		$s6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" fullword ascii
		$s7 = "Content-Type: multipart/form-data; boundary=--MULTI-PARTS-FORM-DATA-BOUNDARY" fullword ascii
		$s8 = "in Json::Value::find" fullword ascii
		$s9 = "in Json::Value::resolveReference" fullword ascii
		$s10 = "in Json::Value::duplicateAndPrefixStringValue" fullword ascii
		$s11 = ".?AVLogicError@Json@@" fullword ascii
		$s12 = ".?AVRuntimeError@Json@@" fullword ascii
		$s13 = "http:\\\\82.221.101.157:80" ascii
		$s14 = "http://172.223.112.130:80" ascii
		$s15 = "http://172.223.112.130:443" ascii
		$s16 = "http://info.newsrental.net:80" ascii
		$s17 = "%s|%I64d" ascii
		$s18 = "open internet failed..." ascii
		$s19 = "connect failed..." ascii
		$s20 = "handle not opened..." ascii
		$s21 = "corrupted regex pattern" fullword ascii
		$s22 = "add cookie failed..." ascii

	condition:
		uint16(0)==0x5a4d and 14 of them
}
