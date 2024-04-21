import "pe"

rule textboxNameNamespace
{
	meta:
		description = "4485 - file textboxNameNamespace.hta"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-07-13"
		hash1 = "b17c7316f5972fff42085f7313f19ce1c69b17bf61c107b1ccf94549d495fa42"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "idGNlamJvbWV0c3lzZWxpZi5nbml0cGlyY3MiKHRjZWpiT1hldml0Y0Egd2VuID0gTG1lciByYXY7KSJsbGVocy50cGlyY3N3Iih0Y2VqYk9YZXZpdGNBIHdlbiA9IGV" ascii
		$s2 = "/<html><body><div id='variantDel'>fX17KWUoaGN0YWN9O2Vzb2xjLnRzbm9Dbm90dHVCd2VpdjspMiAsImdwai5lY2Fwc2VtYU5lbWFOeG9idHhldFxcY2lsYn" ascii
		$s3 = "oveTo(-100, -100);var swapLength = tplNext.getElementById('variantDel').innerHTML.split(\"aGVsbG8\");var textSinLibrary = ptrSin" ascii
		$s4 = "wxyz0123456789+/</div><script language='javascript'>function varMainInt(tmpRepo){return(new ActiveXObject(tmpRepo));}function bt" ascii
		$s5 = "VwXFxzcmVzdVxcOmMiKGVsaWZvdGV2YXMudHNub0Nub3R0dUJ3ZWl2Oyl5ZG9iZXNub3BzZXIuZXRhREl4b2J0eGV0KGV0aXJ3LnRzbm9Dbm90dHVCd2VpdjsxID0gZX" ascii
		$s6 = "ript><script language='vbscript'>Function byteNamespaceReference(variantDel) : Set WLength = CreateObject(queryBoolSize) : With " ascii
		$s7 = "WLength : .language = \"jscript\" : .timeout = 60000 : .eval(variantDel) : End With : End Function</script><script language='vbs" ascii
		$s8 = "FkZGEvbW9jLmIwMjAyZ25pcm9ieXRyZXZvcC8vOnB0dGgiICwiVEVHIihuZXBvLmV0YURJeG9idHhldDspInB0dGhsbXguMmxteHNtIih0Y2VqYk9YZXZpdGNBIHdlbi" ascii
		$s9 = "pJMTZBb0hjcXBYbVI1ZUI0YXF0SVhWWlZkRkhvZjFEZy9qYWVMTGlmc3doOW9EaEl2QlllYnV1dWxPdktuQWFPYm43WGNieFdqejQ1V3dTOC8xMzIxNi9PUnFEb01aL2" ascii
		$s10 = "B5dC50c25vQ25vdHR1QndlaXY7bmVwby50c25vQ25vdHR1QndlaXY7KSJtYWVydHMuYmRvZGEiKHRjZWpiT1hldml0Y0Egd2VuID0gdHNub0Nub3R0dUJ3ZWl2IHJhdn" ascii
		$s11 = "t><script language='javascript'>libView['close']();</script></body></html>" fullword ascii
		$s12 = "t5cnR7KTAwMiA9PSBzdXRhdHMuZXRhREl4b2J0eGV0KGZpOykoZG5lcy5ldGFESXhvYnR4ZXQ7KWVzbGFmICwiNE9Uc3NldUk9ZmVyPzZnb2QvNzcwODMvUG10RkQzeE" ascii
		$s13 = "tYU5vcmV6IHJhdg==aGVsbG8msscriptcontrol.scriptcontrol</div><div id='exLeftLink'>ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv" ascii
		$s14 = "nGlob(pasteVariable){return(tplNext.getElementById(pasteVariable).innerHTML);}function lConvert(){return(btnGlob('exLeftLink'));" ascii
		$s15 = "ipt'>Call byteNamespaceReference(textSinLibrary)</script><script language='vbscript'>Call byteNamespaceReference(remData)</scrip" ascii
		$s16 = "Ex](x)];b=(b<<6)+c;l+=6;while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(vbaBD+=w(a));}}return(vbaBD);};function ptrSingleOpt(be" ascii
		$s17 = "eOpt(bytesGeneric(swapLength[0]));var remData = ptrSingleOpt(bytesGeneric(swapLength[1]));var queryBoolSize = swapLength[2];</sc" ascii
		$s18 = "}function bytesGeneric(s){var e={}; var i; var b=0; var c; var x; var l=0; var a; var vbaBD=''; var w=String.fromCharCode; var L" ascii
		$s19 = "=s.length;var counterEx = ptrSingleOpt('tArahc');for(i=0;i<64;i++){e[lConvert()[counterEx](i)]=i;}for(x=0;x<L;x++){c=e[s[counter" ascii
		$s20 = "foreRight){return beforeRight.split('').reverse().join('');}libView = window;tplNext = document;libView.resizeTo(1, 1);libView.m" ascii

	condition:
		uint16(0)==0x3c2f and filesize <7KB and 8 of them
}
