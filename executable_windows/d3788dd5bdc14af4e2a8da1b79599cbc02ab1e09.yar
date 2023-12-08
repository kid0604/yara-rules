rule Win_Ransomware_Teslacrypt_21
{
	meta:
		description = "Detect the risk of Ransomware TeslaCrypt Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 4f6e6520646179206166746572[0-20]474f5020686f706566756c20616674657220527562696f2064726f7073 }

	condition:
		all of them
}
