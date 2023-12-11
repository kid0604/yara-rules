import "pe"

rule pvz_in
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "LAST_TIME=00/00/0000:00:00PM$"
		$s2 = "if %%ERRORLEVEL%% == 1 GOTO line"

	condition:
		all of them
}
