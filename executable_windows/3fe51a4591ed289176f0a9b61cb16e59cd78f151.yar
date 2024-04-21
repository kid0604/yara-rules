import "pe"

rule case_4778_theora2
{
	meta:
		description = "4778 - file theora2.dll"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-15"
		hash1 = "92db40988d314cea103ecc343b61188d8b472dc524c5b66a3776dad6fc7938f0"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = " consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii
		$s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		$s3 = "keywords\" content=\"w3.org/1999/xhtml\"><a target=\"_blank\" text/html; charset=\" target=\"_blank\"><table cellpadding=\"autoc" ascii
		$s4 = "erturkey);var forestgivingerrorsDomain}else{insertBlog</footerlogin.fasteragents<body 10px 0pragmafridayjuniordollarplacedcovers" ascii
		$s5 = " severalbecomesselect wedding00.htmlmonarchoff theteacherhighly biologylife ofor evenrise of&raquo;plusonehunting(thoughDouglasj" ascii
		$s6 = "font></Norwegianspecifiedproducingpassenger(new DatetemporaryfictionalAfter theequationsdownload.regularlydeveloperabove thelink" ascii
		$s7 = "Besides//--></able totargetsessencehim to its by common.mineralto takeways tos.org/ladvisedpenaltysimple:if theyLettersa shortHe" ascii
		$s8 = " attemptpair ofmake itKontaktAntoniohaving ratings activestreamstrapped\").css(hostilelead tolittle groups,Picture-->" fullword ascii
		$s9 = "<script type== document.createElemen<a target=\"_blank\" href= document.getElementsBinput type=\"text\" name=a.type = 'text/java" ascii
		$s10 = "ondisciplinelogo.png\" (document,boundariesexpressionsettlementBackgroundout of theenterprise(\"https:\" unescape(\"password\" d" ascii
		$s11 = "Dwrite.dll" fullword wide
		$s12 = " rows=\" objectinverse<footerCustomV><\\/scrsolvingChamberslaverywoundedwhereas!= 'undfor allpartly -right:Arabianbacked century" ascii
		$s13 = "online.?xml vehelpingdiamonduse theairlineend -->).attr(readershosting#ffffffrealizeVincentsignals src=\"/Productdespitediverset" ascii
		$s14 = "changeresultpublicscreenchoosenormaltravelissuessourcetargetspringmodulemobileswitchphotosborderregionitselfsocialactivecolumnre" ascii
		$s15 = "put type=\"hidden\" najs\" type=\"text/javascri(document).ready(functiscript type=\"text/javasimage\" content=\"http://UA-Compat" ascii
		$s16 = "alsereadyaudiotakeswhile.com/livedcasesdailychildgreatjudgethoseunitsneverbroadcoastcoverapplefilescyclesceneplansclickwritequee" ascii
		$s17 = " the would not befor instanceinvention ofmore complexcollectivelybackground: text-align: its originalinto accountthis processan " ascii
		$s18 = "came fromwere usednote thatreceivingExecutiveeven moreaccess tocommanderPoliticalmusiciansdeliciousprisonersadvent ofUTF-8\" /><" ascii
		$s19 = "Lib1.dll" fullword ascii
		$s20 = "AppPolicyGetProcessTerminationMethod" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <9000KB and 1 of ($x*) and all of them
}
