rule Ammyy_Admin_AA_v3
{
	meta:
		description = "Remote Admin Tool used by APT group Anunak (ru) - file AA_v3.4.exe and AA_v3.5.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/gkAg2E"
		date = "2014/12/22"
		score = 55
		hash1 = "b130611c92788337c4f6bb9e9454ff06eb409166"
		hash2 = "07539abb2623fe24b9a05e240f675fa2d15268cb"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "S:\\Ammyy\\sources\\target\\TrService.cpp" fullword ascii
		$x2 = "S:\\Ammyy\\sources\\target\\TrDesktopCopyRect.cpp" fullword ascii
		$x3 = "Global\\Ammyy.Target.IncomePort" fullword ascii
		$x4 = "S:\\Ammyy\\sources\\target\\TrFmFileSys.cpp" fullword ascii
		$x5 = "Please enter password for accessing remote computer" fullword ascii
		$s1 = "CreateProcess1()#3 %d error=%d" fullword ascii
		$s2 = "CHttpClient::SendRequest2(%s, %s, %d) error: invalid host name." fullword ascii
		$s3 = "ERROR: CreateProcessAsUser() error=%d, session=%d" fullword ascii
		$s4 = "ERROR: FindProcessByName('explorer.exe')" fullword ascii

	condition:
		2 of ($x*) or all of ($s*)
}
