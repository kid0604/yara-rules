import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_JS_Hex_B64Encoded_EXE
{
	meta:
		author = "ditekSHen"
		description = "Detects JavaScript files hex and base64 encoded executables"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = ".SaveToFile" ascii
		$s2 = ".Run" ascii
		$s3 = "ActiveXObject" ascii
		$s4 = "fromCharCode" ascii
		$s5 = "\\x66\\x72\\x6F\\x6D\\x43\\x68\\x61\\x72\\x43\\x6F\\x64\\x65" ascii
		$binary = "\\x54\\x56\\x71\\x51\\x41\\x41" ascii
		$pattern = /[\s\{\(\[=]_0x[0-9a-z]{3,6}/ ascii

	condition:
		$binary and $pattern and 2 of ($s*) and filesize <2500KB
}
