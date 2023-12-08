import "math"
import "pe"

rule hta_VBS
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 8"
		os = "windows"
		filetype = "script"

	strings:
		$str = "myAr\"&\"ray \"&Chr(61)&\" Array\"&Chr(40)&Chr(45)&\"4\"&Chr(44)&Chr(45)&\"24\"&Chr(44)&Chr(45)&\"119\"&Chr(44)"

	condition:
		uint16(0)!=0x5A4D and $str
}
