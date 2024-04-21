rule files_dhvqx
{
	meta:
		description = "9893_files - file dhvqx.aspx"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
		date = "2022-03-21"
		hash1 = "c5aae30675cc1fd83fd25330cec245af744b878a8f86626d98b8e7fcd3e970f8"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "eval(Request['exec_code'],'unsafe');Response.End;" fullword ascii
		$s2 = "6<script language='JScript' runat='server'>" fullword ascii
		$s3 = "AEALAAAAAAAAAAA" fullword ascii
		$s4 = "AFAVAJA" fullword ascii
		$s5 = "AAAAAAV" fullword ascii
		$s6 = "LAAAAAAA" fullword ascii
		$s7 = "ANAZAQA" fullword ascii
		$s8 = "ALAAAAA" fullword ascii
		$s9 = "AAAAAEA" ascii
		$s10 = "ALAHAUA" fullword ascii

	condition:
		uint16(0)==0x4221 and filesize <800KB and ($s1 and $s2) and 4 of them
}
