import "pe"

rule csext
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "COM+ System Extentions"
		$s2 = "csext.exe"
		$s3 = "COM_Extentions_bin"

	condition:
		all of them
}
