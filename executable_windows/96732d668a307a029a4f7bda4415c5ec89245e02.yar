rule CN_Toolset_sig_1433_135_sqlr
{
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
		$s11 = ";DATABASE=master" fullword ascii
		$s12 = "xp_cmdshell '" fullword ascii
		$s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii

	condition:
		all of them
}
