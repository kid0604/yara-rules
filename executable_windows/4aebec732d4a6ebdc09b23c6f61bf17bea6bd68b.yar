import "pe"

rule LoggerModule
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s-%02d%02d%02d%02d%02d.r"
		$s2 = "C:\\Users\\%s\\AppData\\Cookies\\"

	condition:
		all of them
}
