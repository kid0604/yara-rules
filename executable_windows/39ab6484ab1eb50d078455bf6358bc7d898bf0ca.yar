import "pe"

rule case_4778_filepass
{
	meta:
		description = "4778 - file filepass.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-15"
		hash1 = "8358c51b34f351da30450956f25bef9d5377a993a156c452b872b3e2f10004a8"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = " consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii
		$s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		$s3 = "keywords\" content=\"w3.org/1999/xhtml\"><a target=\"_blank\" text/html; charset=\" target=\"_blank\"><table cellpadding=\"autoc" ascii
		$s4 = " <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii
		$s5 = "erturkey);var forestgivingerrorsDomain}else{insertBlog</footerlogin.fasteragents<body 10px 0pragmafridayjuniordollarplacedcovers" ascii
		$s6 = " severalbecomesselect wedding00.htmlmonarchoff theteacherhighly biologylife ofor evenrise of&raquo;plusonehunting(thoughDouglasj" ascii
		$s7 = "font></Norwegianspecifiedproducingpassenger(new DatetemporaryfictionalAfter theequationsdownload.regularlydeveloperabove thelink" ascii
		$s8 = "Besides//--></able totargetsessencehim to its by common.mineralto takeways tos.org/ladvisedpenaltysimple:if theyLettersa shortHe" ascii
		$s9 = " attemptpair ofmake itKontaktAntoniohaving ratings activestreamstrapped\").css(hostilelead tolittle groups,Picture-->" fullword ascii
		$s10 = " <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii
		$s11 = "<script type== document.createElemen<a target=\"_blank\" href= document.getElementsBinput type=\"text\" name=a.type = 'text/java" ascii
		$s12 = "ondisciplinelogo.png\" (document,boundariesexpressionsettlementBackgroundout of theenterprise(\"https:\" unescape(\"password\" d" ascii
		$s13 = "DirectSound: failed to load DSOUND.DLL" fullword ascii
		$s14 = "theora2.dll" fullword ascii
		$s15 = "bin\\XInput1_3.dll" fullword wide
		$s16 = " rows=\" objectinverse<footerCustomV><\\/scrsolvingChamberslaverywoundedwhereas!= 'undfor allpartly -right:Arabianbacked century" ascii
		$s17 = "InputMapper.exe" fullword ascii
		$s18 = "C:\\0\\Release\\output\\Release\\spdblib\\output\\Release_TS\\release\\saslPLAIN\\Relea.pdb" fullword ascii
		$s19 = "DS4Windows.exe" fullword ascii
		$s20 = "online.?xml vehelpingdiamonduse theairlineend -->).attr(readershosting#ffffffrealizeVincentsignals src=\"/Productdespitediverset" ascii

	condition:
		uint16(0)==0x5a4d and filesize <19000KB and 1 of ($x*) and all of them
}
