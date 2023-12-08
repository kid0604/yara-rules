private rule PotaoSecondStage
{
	meta:
		description = "Yara rule for detecting Potao second stage malware"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$binary1 = {51 7A BB 85 [10-180] E8 47 D2 A8}
		$binary2 = {5F 21 63 DD [10-30] EC FD 33 02}
		$binary3 = {CA 77 67 57 [10-30] BA 08 20 7A}
		$str1 = "?AVCrypt32Import@@"
		$str2 = "%.5llx"

	condition:
		($mz at 0) and any of ($binary*) and any of ($str*)
}
