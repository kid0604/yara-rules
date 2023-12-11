import "math"

rule WEBSHELL_PHP_Base64_Encoded_Payloads : FILE
{
	meta:
		description = "php webshell containing base64 encoded payload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "88d0d4696c9cb2d37d16e330e236cb37cfaec4cd"
		hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
		hash = "e726cd071915534761822805724c6c6bfe0fcac604a86f09437f03f301512dc5"
		hash = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
		hash = "8cc9802769ede56f1139abeaa0735526f781dff3b6c6334795d1d0f19161d076"
		hash = "4cda0c798908b61ae7f4146c6218d7b7de14cbcd7c839edbdeb547b5ae404cd4"
		hash = "afd9c9b0df0b2ca119914ea0008fad94de3bd93c6919f226b793464d4441bdf4"
		hash = "b2048dc30fc7681094a0306a81f4a4cc34f0b35ccce1258c20f4940300397819"
		hash = "da6af9a4a60e3a484764010fbf1a547c2c0a2791e03fc11618b8fc2605dceb04"
		hash = "222cd9b208bd24955bcf4f9976f9c14c1d25e29d361d9dcd603d57f1ea2b0aee"
		hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
		hash = "6b6cd1ef7e78e37cbcca94bfb5f49f763ba2f63ed8b33bc4d7f9e5314c87f646"
		hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
		hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
		hash = "e2b1dfcfaa61e92526a3a444be6c65330a8db4e692543a421e19711760f6ffe2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$decode1 = "base64_decode" fullword nocase wide ascii
		$decode2 = "openssl_decrypt" fullword nocase wide ascii
		$one1 = "leGVj"
		$one2 = "V4ZW"
		$one3 = "ZXhlY"
		$one4 = "UAeABlAGMA"
		$one5 = "lAHgAZQBjA"
		$one6 = "ZQB4AGUAYw"
		$two1 = "zaGVsbF9leGVj"
		$two2 = "NoZWxsX2V4ZW"
		$two3 = "c2hlbGxfZXhlY"
		$two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
		$two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
		$two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
		$three1 = "wYXNzdGhyd"
		$three2 = "Bhc3N0aHJ1"
		$three3 = "cGFzc3Rocn"
		$three4 = "AAYQBzAHMAdABoAHIAdQ"
		$three5 = "wAGEAcwBzAHQAaAByAHUA"
		$three6 = "cABhAHMAcwB0AGgAcgB1A"
		$four1 = "zeXN0ZW"
		$four2 = "N5c3Rlb"
		$four3 = "c3lzdGVt"
		$four4 = "MAeQBzAHQAZQBtA"
		$four5 = "zAHkAcwB0AGUAbQ"
		$four6 = "cwB5AHMAdABlAG0A"
		$five1 = "wb3Blb"
		$five2 = "BvcGVu"
		$five3 = "cG9wZW"
		$five4 = "AAbwBwAGUAbg"
		$five5 = "wAG8AcABlAG4A"
		$five6 = "cABvAHAAZQBuA"
		$six1 = "wcm9jX29wZW"
		$six2 = "Byb2Nfb3Blb"
		$six3 = "cHJvY19vcGVu"
		$six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
		$six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
		$six6 = "cAByAG8AYwBfAG8AcABlAG4A"
		$seven1 = "wY250bF9leGVj"
		$seven2 = "BjbnRsX2V4ZW"
		$seven3 = "cGNudGxfZXhlY"
		$seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
		$seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
		$seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
		$eight1 = "ldmFs"
		$eight2 = "V2YW"
		$eight3 = "ZXZhb"
		$eight4 = "UAdgBhAGwA"
		$eight5 = "lAHYAYQBsA"
		$eight6 = "ZQB2AGEAbA"
		$nine1 = "hc3Nlcn"
		$nine2 = "Fzc2Vyd"
		$nine3 = "YXNzZXJ0"
		$nine4 = "EAcwBzAGUAcgB0A"
		$nine5 = "hAHMAcwBlAHIAdA"
		$nine6 = "YQBzAHMAZQByAHQA"
		$execu1 = "leGVjd"
		$execu2 = "V4ZWN1"
		$execu3 = "ZXhlY3"
		$esystem1 = "lc3lzdGVt"
		$esystem2 = "VzeXN0ZW"
		$esystem3 = "ZXN5c3Rlb"
		$opening1 = "vcGVuaW5n"
		$opening2 = "9wZW5pbm"
		$opening3 = "b3BlbmluZ"
		$fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
		$fp2 = "YXBpLnRlbGVncmFtLm9"
		$fp3 = " GET /"
		$fp4 = " POST /"
		$fpa1 = "/cn=Recipients"
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii

	condition:
		filesize <300KB and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and not any of ($fp*) and any of ($decode*) and (( any of ($one*) and not any of ($execu*)) or any of ($two*) or any of ($three*) or ( any of ($four*) and not any of ($esystem*)) or ( any of ($five*) and not any of ($opening*)) or any of ($six*) or any of ($seven*) or any of ($eight*) or any of ($nine*))
}
